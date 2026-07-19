"""
reset_and_import.py — Reset complet + import ultra-rapide de fichiers JSON/JSONL/CSV dans DuckDB
================================================================================================
Usage :
    python reset_and_import.py C:\\chemin\\vers\\tes\\fichiers
    python reset_and_import.py C:\\data\\json1.json C:\\data\\json2.jsonl C:\\data\\big.csv
    python reset_and_import.py  (sans argument : scanne le dossier osint_data/ à côté du script)

Met les fichiers JSON dans le dossier et lance ce script.
Le backend OSINT (server_v3.py) peut rester en route pendant l'import.

Requis : pip install duckdb ijson
"""

import sys, os, re, json, hashlib, time, logging
from pathlib import Path
from typing import Optional

# ── CONFIG ────────────────────────────────────────────────────────────────────
# Chemin vers le fichier DuckDB du backend OSINT (même que DB_PATH dans server_v3.py)
_SCRIPT_DIR = Path(__file__).parent
DB_PATH = os.environ.get(
    "OSINT_DB_PATH",
    str(_SCRIPT_DIR / "osint_master.duckdb")
)

# Dossier scanné si aucun argument n'est passé
DEFAULT_SCAN_DIR = _SCRIPT_DIR / "osint_data"

BATCH_SIZE   = 300_000     # lignes par INSERT batch (ajuste selon ta RAM)
BIG_FILE_MB  = 100         # au-dessus → mode DuckDB natif ou ijson
EXTS_IMPORT  = {".json", ".jsonl", ".ndjson", ".csv", ".tsv", ".txt"}

# ── LOGGING ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("import")

# ── REGEX ─────────────────────────────────────────────────────────────────────
RE_EMAIL = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
RE_IP    = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
RE_PHONE = re.compile(r"(?:\+|00)(?:\d[\s\-]?){6,14}\d")
RE_HASH  = re.compile(r"\b[0-9a-fA-F]{32,64}\b")

# ── MAPPING COLONNES ──────────────────────────────────────────────────────────
COL_MAP = {
    "email":    ["email", "mail", "courriel", "e_mail", "email_address", "emailaddress"],
    "username": ["username", "user", "login", "pseudo", "nickname", "nick", "name",
                 "nom", "utilisateur", "handle", "user_name", "user_id", "userid",
                 "login_name", "account"],
    "password": ["password", "pass", "pwd", "passwd", "mot_de_passe", "mdp",
                 "hashed_password", "password_hash"],
    "ip":       ["ip", "ip_address", "ipaddress", "addr", "adresse_ip", "ip_addr",
                 "ipv4", "ipv6"],
    "domain":   ["domain", "domaine", "host", "hostname", "site", "website", "url"],
    "phone":    ["phone", "telephone", "tel", "mobile", "cell", "numero", "phone_number",
                 "phonenumber", "msisdn"],
    "hash_val": ["hash", "md5", "sha1", "sha256", "sha512", "hashed", "password_hash",
                 "hash_value"],
}

def _normalize(s: str) -> str:
    return s.lower().strip().replace(" ", "_").replace("-", "_")

def _match_col(name: str) -> Optional[str]:
    n = _normalize(name)
    for field, patterns in COL_MAP.items():
        for pat in patterns:
            if pat == n or pat in n or n in pat:
                return field
    return None

# ── HELPERS ───────────────────────────────────────────────────────────────────
def _stable_id(key: str) -> int:
    h = hashlib.sha1(key.encode("utf-8", errors="replace")).digest()
    return int.from_bytes(h[:8], "big", signed=True)

def _enrich(raw: str) -> dict:
    r: dict = {}
    m = RE_EMAIL.search(raw)
    if m:
        r["email"]  = m.group(0)
        r["domain"] = m.group(0).split("@", 1)[1]
    m = RE_IP.search(raw)
    if m:
        r["ip"] = m.group(0)
    m = RE_PHONE.search(raw)
    if m:
        r["phone"] = m.group(0).strip()
    m = RE_HASH.search(raw)
    if m:
        r["hash_val"] = m.group(0)
    return r

def _safe_raw(raw: str) -> str:
    """Ne garde que les champs non-sensibles dans raw (jamais les mots de passe)."""
    tokens = []
    for rx in (RE_EMAIL, RE_IP, RE_HASH, RE_PHONE):
        for m in rx.findall(raw):
            tokens.append(m if isinstance(m, str) else m[0])
    return " | ".join(dict.fromkeys(tokens))[:1000]

def _row_from_dict(obj: dict, src: str, idx: int) -> dict:
    r: dict = {}
    raw_parts = []
    for k, v in obj.items():
        if v is None:
            continue
        val = str(v).strip()
        if not val:
            continue
        raw_parts.append(val)
        field = _match_col(k)
        if field and val:
            # hash_val et password ne se combinent pas si déjà remplis
            if field not in r:
                r[field] = val

    # Si aucun champ reconnu → enrichissement regex sur les valeurs brutes
    if not any(r.get(f) for f in ("email", "username", "ip", "domain")):
        joined = " ".join(raw_parts)
        r.update(_enrich(joined))

    # Domaine depuis email
    email = r.get("email", "")
    if not r.get("domain") and email and "@" in email:
        r["domain"] = email.split("@", 1)[1]

    r["raw"] = _safe_raw(" ".join(raw_parts))
    return r

def _insert_batch(conn, batch: list[dict], src: str) -> int:
    if not batch:
        return 0
    rows = []
    for i, r in enumerate(batch):
        email    = (r.get("email")    or "").strip()[:500]
        username = (r.get("username") or "").strip()[:500]
        password = (r.get("password") or "")
        domain   = (r.get("domain")   or "").strip()[:255]
        ip       = (r.get("ip")       or "").strip()[:45]
        phone    = (r.get("phone")    or "").strip()[:50]
        hash_val = (r.get("hash_val") or "").strip()[:128]
        raw      = (r.get("raw")      or "")

        if not domain and email and "@" in email:
            domain = email.split("@", 1)[1]

        key = f"{src}|{email}|{username}|{hash_val}|{domain}|{ip}|{i}"
        uid = _stable_id(key)
        rows.append((uid, src, email or None, username or None,
                     bool(password), hash_val or None,
                     domain or None, ip or None, phone or None, raw or None))

    conn.executemany(
        "INSERT INTO records VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT (id) DO NOTHING",
        rows
    )
    return len(rows)

# ── IMPORT JSON NATIF DUCKDB (ultra-rapide pour gros fichiers) ────────────────
def _import_json_native(conn, path: Path, src: str) -> Optional[int]:
    """
    Utilise read_json_auto() de DuckDB pour lire le JSON directement en C++.
    Détecte les colonnes et les mappe vers records.
    Retourne None si DuckDB ne peut pas lire ce fichier (fallback Python).
    """
    safe = str(path).replace("\\", "/").replace("'", "''")
    try:
        # Récupère les colonnes du fichier
        schema = conn.execute(
            f"SELECT column_name FROM (DESCRIBE SELECT * FROM read_json_auto('{safe}', maximum_object_size=104857600) LIMIT 0)"
        ).fetchall()
        cols = [row[0] for row in schema]
    except Exception as e:
        log.debug(f"  read_json_auto schema {src}: {e}")
        return None

    if not cols:
        return None

    # Mappe les colonnes JSON vers les champs records
    mappings = {}
    for col in cols:
        field = _match_col(col)
        if field:
            mappings[col] = field

    # Construis la SELECT pour mapper les colonnes
    sel_parts = []
    used_fields = set()

    for col, field in mappings.items():
        safe_col = f'"{col}"'
        if field == "email" and "email" not in used_fields:
            sel_parts.append(f"TRY_CAST({safe_col} AS VARCHAR) AS email")
            used_fields.add("email")
        elif field == "username" and "username" not in used_fields:
            sel_parts.append(f"TRY_CAST({safe_col} AS VARCHAR) AS username")
            used_fields.add("username")
        elif field == "password" and "password" not in used_fields:
            sel_parts.append(f"TRY_CAST({safe_col} AS VARCHAR) AS password")
            used_fields.add("password")
        elif field == "ip" and "ip" not in used_fields:
            sel_parts.append(f"TRY_CAST({safe_col} AS VARCHAR) AS ip")
            used_fields.add("ip")
        elif field == "domain" and "domain" not in used_fields:
            sel_parts.append(f"TRY_CAST({safe_col} AS VARCHAR) AS domain")
            used_fields.add("domain")
        elif field == "phone" and "phone" not in used_fields:
            sel_parts.append(f"TRY_CAST({safe_col} AS VARCHAR) AS phone")
            used_fields.add("phone")
        elif field == "hash_val" and "hash_val" not in used_fields:
            sel_parts.append(f"TRY_CAST({safe_col} AS VARCHAR) AS hash_val")
            used_fields.add("hash_val")

    # Colonnes non mappées → raw
    unmapped = [f'"{c}"' for c in cols if c not in mappings]
    if unmapped:
        raw_expr = " || ' | ' || ".join(
            [f"COALESCE(TRY_CAST({c} AS VARCHAR), '')" for c in unmapped]
        )
        sel_parts.append(f"{raw_expr} AS raw_extra")
    
    if not sel_parts:
        # Aucune colonne mappée, on prend tout en raw
        all_cols = " || ' | ' || ".join(
            [f"COALESCE(TRY_CAST(\"{c}\" AS VARCHAR), '')" for c in cols]
        )
        sel_parts = [f"{all_cols} AS raw_extra"]

    select_sql = ", ".join(sel_parts)

    try:
        # INSERT natif DuckDB → ultra-rapide (C++ multi-threadé)
        has_password_expr = (
            "password IS NOT NULL AND password <> ''"
            if "password" in used_fields else "FALSE"
        )
        email_expr    = "email"    if "email"    in used_fields else "NULL"
        username_expr = "username" if "username" in used_fields else "NULL"
        domain_expr   = ("COALESCE(domain, CASE WHEN email LIKE '%@%' "
                         "THEN split_part(email,'@',2) ELSE NULL END)"
                         if "domain" in used_fields or "email" in used_fields
                         else "NULL")
        ip_expr       = "ip"       if "ip"       in used_fields else "NULL"
        phone_expr    = "phone"    if "phone"    in used_fields else "NULL"
        hash_expr     = "hash_val" if "hash_val" in used_fields else "NULL"

        # raw = colonnes non mappées (jamais les passwords)
        raw_col = "raw_extra" if unmapped else "NULL"

        conn.execute(f"""
            INSERT INTO records
            SELECT
                hash('{src}' || COALESCE({email_expr},'') || COALESCE({username_expr},'')
                     || COALESCE({hash_expr},'') || COALESCE({ip_expr},'')
                     || COALESCE({domain_expr},'') || CAST(row_number() OVER() AS VARCHAR))
                    AS id,
                '{src}'         AS src,
                {email_expr}    AS email,
                {username_expr} AS username,
                ({has_password_expr}) AS password_set,
                {hash_expr}     AS hash_val,
                {domain_expr}   AS domain,
                {ip_expr}       AS ip,
                {phone_expr}    AS phone,
                {raw_col}       AS raw
            FROM (
                SELECT {select_sql}
                FROM read_json_auto('{safe}', maximum_object_size=104857600,
                                    ignore_errors=true)
            ) t
            ON CONFLICT (id) DO NOTHING
        """)
        count = conn.execute(
            f"SELECT COUNT(*) FROM records WHERE src = '{src}'"
        ).fetchone()[0]
        return count
    except Exception as e:
        log.debug(f"  native INSERT {src}: {e}")
        return None

# ── IMPORT JSONL STREAMING (ligne par ligne, sans ijson) ──────────────────────
def _import_jsonl_stream(conn, path: Path, src: str) -> int:
    """JSONL/NDJSON : un objet JSON par ligne. Streaming pur sans charger en mémoire."""
    total = 0
    batch: list[dict] = []

    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line in ("[", "]"):
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    batch.append(_row_from_dict(obj, src, len(batch)))
                elif isinstance(obj, list):
                    for item in obj:
                        if isinstance(item, dict):
                            batch.append(_row_from_dict(item, src, len(batch)))
                else:
                    r = _enrich(str(obj)); r["raw"] = _safe_raw(str(obj))
                    batch.append(r)
            except json.JSONDecodeError:
                r = _enrich(line); r["raw"] = _safe_raw(line)
                batch.append(r)

            if len(batch) >= BATCH_SIZE:
                total += _insert_batch(conn, batch, src)
                conn.commit(); batch.clear()
                log.info(f"  {src}: {total:,} records…")

    if batch:
        total += _insert_batch(conn, batch, src)
        conn.commit()
    return total



def _import_json_python(conn, path: Path, src: str) -> int:
    """Fallback Python pour JSON non standard. Utilise ijson si dispo."""
    total = 0
    batch: list[dict] = []
    file_size = path.stat().st_size

    def flush(b):
        nonlocal total
        total += _insert_batch(conn, b, src)
        conn.commit()

    try:
        import ijson
        log.info(f"  → ijson streaming ({file_size / 1e9:.2f} GB)")
        with path.open("rb") as f:
            for obj in ijson.items(f, "item"):
                if isinstance(obj, dict):
                    batch.append(_row_from_dict(obj, src, len(batch)))
                elif isinstance(obj, str):
                    r = _enrich(obj)
                    r["raw"] = _safe_raw(obj)
                    batch.append(r)
                if len(batch) >= BATCH_SIZE:
                    flush(batch); batch.clear()
                    log.info(f"  {src}: {total:,} records…")
        if batch:
            flush(batch)
        return total
    except ImportError:
        pass

    # Sans ijson → ligne par ligne (JSONL ou JSON array)
    log.info(f"  → streaming ligne par ligne")
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line in ("[", "]", "{", "}"):
                continue
            # enlève virgule finale dans un array
            line = line.rstrip(",")
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    batch.append(_row_from_dict(obj, src, len(batch)))
                elif isinstance(obj, list):
                    for item in obj:
                        if isinstance(item, dict):
                            batch.append(_row_from_dict(item, src, len(batch)))
                else:
                    r = _enrich(str(obj)); r["raw"] = _safe_raw(str(obj))
                    batch.append(r)
            except json.JSONDecodeError:
                r = _enrich(line); r["raw"] = _safe_raw(line)
                batch.append(r)

            if len(batch) >= BATCH_SIZE:
                flush(batch); batch.clear()
                log.info(f"  {src}: {total:,} records…")

    if batch:
        flush(batch)
    return total

# ── IMPORT CSV/TSV ────────────────────────────────────────────────────────────
def _import_csv_native(conn, path: Path, src: str) -> Optional[int]:
    """Import CSV via read_csv_auto de DuckDB."""
    safe = str(path).replace("\\", "/").replace("'", "''")
    try:
        schema = conn.execute(
            f"SELECT column_name FROM (DESCRIBE SELECT * FROM read_csv_auto('{safe}', ignore_errors=true) LIMIT 0)"
        ).fetchall()
        cols = [row[0] for row in schema]
    except Exception as e:
        log.debug(f"  csv schema {src}: {e}")
        return None

    mappings = {col: _match_col(col) for col in cols if _match_col(col)}
    sel = ", ".join(
        [f'TRY_CAST("{c}" AS VARCHAR) AS {f}' for c, f in mappings.items()]
        + [f'COALESCE(TRY_CAST("{c}" AS VARCHAR),\'\')' for c in cols if c not in mappings]
    )
    used = set(mappings.values())

    try:
        conn.execute(f"""
            INSERT INTO records
            SELECT
                hash('{src}' || COALESCE({"email" if "email" in used else "NULL"},'')
                     || COALESCE({"username" if "username" in used else "NULL"},'')
                     || CAST(row_number() OVER() AS VARCHAR)) AS id,
                '{src}' AS src,
                {"email" if "email" in used else "NULL"},
                {"username" if "username" in used else "NULL"},
                {"password IS NOT NULL AND password <> ''" if "password" in used else "FALSE"},
                {"hash_val" if "hash_val" in used else "NULL"},
                {"COALESCE(domain, CASE WHEN email LIKE '%@%' THEN split_part(email,'@',2) ELSE NULL END)" if "domain" in used or "email" in used else "NULL"},
                {"ip" if "ip" in used else "NULL"},
                {"phone" if "phone" in used else "NULL"},
                NULL AS raw
            FROM (SELECT {sel} FROM read_csv_auto('{safe}', ignore_errors=true)) t
            ON CONFLICT (id) DO NOTHING
        """)
        return conn.execute(f"SELECT COUNT(*) FROM records WHERE src='{src}'").fetchone()[0]
    except Exception as e:
        log.debug(f"  csv insert {src}: {e}")
        return None

# ── DISPATCHER ────────────────────────────────────────────────────────────────
def import_file(conn, path: Path) -> int:
    src  = path.name
    ext  = path.suffix.lower()
    size = path.stat().st_size
    size_mb = size / 1024 / 1024
    size_gb = size / 1e9

    log.info(f"📂 {src}  ({size_gb:.2f} GB)" if size_gb >= 0.1 else f"📂 {src}  ({size_mb:.1f} MB)")
    t0 = time.time()

    total = 0

    if ext in (".csv", ".tsv"):
        total = _import_csv_native(conn, path, src) or 0
        if not total:
            # fallback Python CSV
            import csv as _csv
            batch: list[dict] = []
            with path.open("r", encoding="utf-8", errors="replace") as f:
                sample = "".join(f.readline() for _ in range(5))
            try:
                dialect = _csv.Sniffer().sniff(sample, delimiters=":,;|\t")
                sep = dialect.delimiter
            except Exception:
                sep = ","
            with path.open("r", encoding="utf-8", errors="replace") as f:
                reader = _csv.DictReader(f, delimiter=sep)
                for row in reader:
                    batch.append(_row_from_dict(row, src, len(batch)))
                    if len(batch) >= BATCH_SIZE:
                        total += _insert_batch(conn, batch, src)
                        conn.commit(); batch.clear()
            if batch:
                total += _insert_batch(conn, batch, src)
                conn.commit()

    elif ext in (".json", ".jsonl", ".ndjson"):
        # Toujours essayer DuckDB natif d'abord (BEAUCOUP plus rapide)
        result = _import_json_native(conn, path, src)
        if result is not None:
            total = result
        else:
            # Pour JSONL : ijson attend un array, pas des objets séparés → streaming direct
            if ext in (".jsonl", ".ndjson"):
                total = _import_jsonl_stream(conn, path, src)
            else:
                total = _import_json_python(conn, path, src)

    else:
        # .txt et autres délimités → enrichissement regex ligne par ligne
        batch = []
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                r = _enrich(line)
                r["raw"] = _safe_raw(line)
                batch.append(r)
                if len(batch) >= BATCH_SIZE:
                    total += _insert_batch(conn, batch, src)
                    conn.commit(); batch.clear()
        if batch:
            total += _insert_batch(conn, batch, src)
            conn.commit()

    elapsed = time.time() - t0
    rate    = total / elapsed if elapsed > 0 else 0
    log.info(f"  ✓ {total:,} records  en {elapsed:.1f}s  ({rate:,.0f} rec/s)")
    return total

# ── RESET COMPLET ─────────────────────────────────────────────────────────────
def reset_database(conn):
    log.info("🗑️  Reset complet de la base DuckDB…")

    # Supprime TOUTES les tables existantes (y compris celles de l'importer)
    tables = conn.execute(
        "SELECT table_name FROM information_schema.tables WHERE table_schema='main'"
    ).fetchall()
    for (t,) in tables:
        try:
            conn.execute(f'DROP TABLE IF EXISTS "{t}" CASCADE')
            log.info(f"  supprimé : {t}")
        except Exception as e:
            log.warning(f"  impossible de supprimer {t} : {e}")

    # Recrée la table records + imported (structure identique à server_v3.py)
    conn.execute("""
        CREATE TABLE records (
            id           BIGINT PRIMARY KEY,
            src          VARCHAR,
            email        VARCHAR,
            username     VARCHAR,
            password_set BOOLEAN,
            hash_val     VARCHAR,
            domain       VARCHAR,
            ip           VARCHAR,
            phone        VARCHAR,
            raw          VARCHAR
        )
    """)
    conn.execute(
        "CREATE TABLE imported (path VARCHAR PRIMARY KEY, mtime DOUBLE, rows BIGINT)"
    )

    # Index sur tous les champs de recherche
    for col in ("email", "username", "domain", "ip", "phone", "hash_val"):
        conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{col} ON records({col})")

    conn.commit()
    log.info("✅ Base réinitialisée (tables records + imported + index)")

# ── MAIN ──────────────────────────────────────────────────────────────────────
def collect_files(args: list[str]) -> list[Path]:
    files = []
    if not args:
        # Pas d'argument → scanne osint_data/
        if DEFAULT_SCAN_DIR.exists():
            for p in DEFAULT_SCAN_DIR.rglob("*"):
                if p.is_file() and p.suffix.lower() in EXTS_IMPORT:
                    files.append(p)
        else:
            log.warning(f"Dossier par défaut introuvable : {DEFAULT_SCAN_DIR}")
            log.warning("Usage : python reset_and_import.py <dossier_ou_fichiers...>")
    else:
        for arg in args:
            p = Path(arg)
            if p.is_dir():
                for f in p.rglob("*"):
                    if f.is_file() and f.suffix.lower() in EXTS_IMPORT:
                        files.append(f)
            elif p.is_file():
                files.append(p)
            else:
                log.warning(f"Introuvable : {arg}")
    return files


def main():
    args = sys.argv[1:]
    files = collect_files(args)

    if not files:
        log.error("Aucun fichier à importer. Vérifie le chemin.")
        sys.exit(1)

    total_size = sum(f.stat().st_size for f in files if f.exists()) / 1e9
    log.info(f"🔍 {len(files)} fichier(s) trouvé(s)  —  {total_size:.2f} GB au total")
    log.info(f"🗄️  Base DuckDB : {DB_PATH}")

    import duckdb
    conn = duckdb.connect(DB_PATH, config={
        "threads":                8,
        "memory_limit":           "10GB",
        "max_temp_directory_size": "20GB",
    })

    # ── 1. RESET ──
    reset_database(conn)

    # ── 2. IMPORT ──
    grand_total = 0
    t_start = time.time()

    for i, path in enumerate(files, 1):
        log.info(f"\n[{i}/{len(files)}] {path.name}")
        try:
            n = import_file(conn, path)
            grand_total += n
            # Marque comme importé
            conn.execute(
                "INSERT INTO imported VALUES(?,?,?) ON CONFLICT (path) DO UPDATE SET mtime=excluded.mtime, rows=excluded.rows",
                [str(path), path.stat().st_mtime, n]
            )
            conn.commit()
        except Exception as e:
            log.error(f"  ❌ Erreur sur {path.name} : {e}")

    elapsed = time.time() - t_start
    log.info(f"\n{'='*60}")
    log.info(f"✅  Import terminé en {elapsed:.1f}s")
    log.info(f"📊  Total records dans DuckDB : {grand_total:,}")
    log.info(f"🗄️   Fichier : {DB_PATH}")
    log.info(f"{'='*60}")

    conn.close()


if __name__ == "__main__":
    main()
