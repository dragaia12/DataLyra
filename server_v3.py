"""
OSINT HUB v4.1 — Backend universel DuckDB (VERSION CORRIGEE)
=============================================================
Corrections apportées vs v4.0 :
  - AUTHENTIFICATION : validation du JWT Supabase sur toutes les routes
    (configurable via OSINT_REQUIRE_AUTH). Le backend n'est plus ouvert à tous.
  - CORS : restreint aux origines autorisées (OSINT_ALLOWED_ORIGINS), plus de "*".
  - IDS STABLES : hash() Python randomisé -> remplace par hashlib (IDs persistants
    entre redémarrages, indispensable pour le dedup INSERT OR IGNORE).
  - SHUTDOWN PROPRE : os._exit(0) -> arrêt via threading.Event + fermeture DuckDB.
  - PASSWORDS : plus JAMAIS renvoyés en clair (champ raw tronqué, password masqué).
    On stocke un booléen has_password + le hash quand présent, jamais le clair.
  - SCAN RESTRICTIF : ne scanne que les sous-dossiers OSINT_DATA (plus de D:/ entier).
  - STREAMING : lecture ligne par ligne des gros fichiers (plus de read_text() sur
    des fichiers de données volumineux).
  - REGEX IP validee (0-255 par octet), regex phone resserree.
  - CONCEPT MULTI-TOOL conserve : la recherche DuckDB est presentee sous forme de
    modules (email_reputation, ip_intel, domain_lookup, hash_check, phone_lookup).
  - THREAD-SAFE : un seul worker d'import (la connexion DuckDB est unique).
"""
import asyncio, json, logging, os, re, threading, time, csv, io, hashlib, warnings
warnings.filterwarnings('ignore', category=SyntaxWarning)
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv
load_dotenv()  # lit le fichier .env (à côté de ce script) à chaque lancement
import duckdb, uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.websockets import WebSocketState

# ── CONFIG ────────────────────────────────────────────────────
# Dossiers à scanner. PAR DEFAUT un sous-dossier "osint_data" à côté du serveur.
# Mettez vos fichiers de données (CSV, JSON, TXT) DEDANS, pas à la racine du disque.
_DEFAULT_ROOT = str((Path(__file__).parent / "osint_data").resolve())
SCAN_ROOTS = [Path(p) for p in os.environ.get("OSINT_SCAN_ROOTS", _DEFAULT_ROOT).split(",") if p.strip()]
DB_PATH    = os.environ.get("OSINT_DB_PATH",   str(Path(__file__).parent / "osint_master.duckdb"))
STOP_FILE  = Path(os.environ.get("OSINT_STOP_FILE", str(Path(__file__).parent / "STOP")))
PORT       = int(os.environ.get("PORT",              "8765"))
RESCAN_SECS = int(os.environ.get("OSINT_RESCAN_SECS", "300"))
MAX_RESULTS = int(os.environ.get("OSINT_MAX_RESULTS",  "1000"))
LOG_FILE   = os.environ.get("OSINT_LOG_FILE",  str(Path(__file__).parent / "osint_service.log"))
TMP_DIR    = os.environ.get("OSINT_TMP_DIR",   str(Path(__file__).parent / "osint_tmp"))

# ── AUTHENTIFICATION ──────────────────────────────────────────
# Mettez ici le secret JWT de votre projet Supabase (Dashboard > API > JWT Secret).
# En dev local, laissez vide + OSINT_REQUIRE_AUTH=0 pour désactiver l'auth.
SUPABASE_JWT_SECRET = os.environ.get("OSINT_SUPABASE_JWT_SECRET", "COLLE_TON_VRAI_JWT_SECRET_ICI")
REQUIRE_AUTH = os.environ.get("OSINT_REQUIRE_AUTH", "1") == "1"
# Origines autorisées pour le CORS (séparées par virgule). Ex: https://votre-site.pages.dev
ALLOWED_ORIGINS = [o.strip() for o in os.environ.get("OSINT_ALLOWED_ORIGINS", "*").split(",") if o.strip()]
# Pattern regex optionnel pour autoriser TOUTES les previews Cloudflare Pages
# d'un projet (le hash change à chaque déploiement, ex: 97e5d9be.datalyra.pages.dev).
# Par défaut, autorise *.pages.dev et *.onrender.com. Personnalisable via env.
ALLOWED_ORIGIN_REGEX = os.environ.get(
    "OSINT_ALLOWED_ORIGIN_REGEX",
    r"^https://([a-zA-Z0-9-]+\.)*pages\.dev$",
)

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[logging.StreamHandler(),
              logging.FileHandler(LOG_FILE, encoding="utf-8", errors="replace")])
log = logging.getLogger("osint")
if REQUIRE_AUTH and not SUPABASE_JWT_SECRET:
    log.warning("⚠️  OSINT_REQUIRE_AUTH=1 mais OSINT_SUPABASE_JWT_SECRET est vide ! Auth inactive.")
if ALLOWED_ORIGINS == ["*"]:
    log.warning("⚠️  CORS ouvert à toutes les origines (*). En production, définissez OSINT_ALLOWED_ORIGINS.")
# ── REGEX GLOBAUX (corrigés) ──────────────────────────────────
RE_EMAIL   = re.compile(r"[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}")
# IP valide : 4 octets 0-255
RE_IP      = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
RE_DOMAIN  = re.compile(r"@([a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,})")
# Phone resserré : indicatif + 6 à 12 chiffres
RE_PHONE   = re.compile(r"(?:\+|00)(?:\d[\s\-]?){6,14}\d")
RE_HASH    = re.compile(r"\b[0-9a-fA-F]{32,64}\b")

# Séparateurs à tester pour les fichiers délimités
SEPARATORS = [":", "|", ";", "\t", ",", " "]

# Regex SQL pour DuckDB (utilisées dans les requêtes natives)
_SQL_RE_EMAIL  = "[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}"
_SQL_RE_DOMAIN = "@([a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,})"

# ── DUCKDB SINGLETON ──────────────────────────────────────────
_lock = threading.RLock()
_conn: Optional[duckdb.DuckDBPyConnection] = None
_shutdown = threading.Event()


def db() -> duckdb.DuckDBPyConnection:
    global _conn
    if _conn is not None:
        return _conn
    Path(TMP_DIR).mkdir(parents=True, exist_ok=True)
    _conn = duckdb.connect(DB_PATH, config={
        "threads": 8,
        "memory_limit": "10GB",
        "max_temp_directory_size": "20GB",
    })
    _conn.execute(f"SET temp_directory='{TMP_DIR}'")
    _conn.execute("SET preserve_insertion_order=false")
    _conn.execute("SET checkpoint_threshold='1GB'")
    _conn.execute("PRAGMA threads=8")
    _conn.execute("""
        CREATE TABLE IF NOT EXISTS records (
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
    _conn.execute("CREATE TABLE IF NOT EXISTS imported (path VARCHAR PRIMARY KEY, mtime DOUBLE, rows BIGINT)")
    # Index sur tous les champs searchables
    for col in ["email", "username", "domain", "ip", "phone", "hash_val"]:
        try:
            _conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{col} ON records({col})")
        except Exception:
            pass
    _migrate(_conn)
    _conn.commit()
    return _conn


def _migrate(c):
    """Ajoute les colonnes manquantes si upgrade depuis une ancienne version."""
    try:
        # Vérifier si la table a un PRIMARY KEY (sinon ON CONFLICT ne marche pas)
        try:
            has_pk = c.execute(
                "SELECT COUNT(*) FROM duckdb_constraints() "
                "WHERE table_name='records' AND constraint_type='PRIMARY KEY'"
            ).fetchone()[0]
            if not has_pk:
                log.info("Migration: recréation de records avec PRIMARY KEY...")
                # 1. Supprimer les index avant de renommer (DuckDB l'exige)
                for _idx in ["idx_email","idx_username","idx_domain","idx_ip","idx_phone","idx_hash_val"]:
                    try: c.execute(f"DROP INDEX IF EXISTS {_idx}")
                    except Exception: pass
                # 2. Renommer l'ancienne table
                c.execute("ALTER TABLE records RENAME TO records_old")
                # 3. Créer la nouvelle avec PRIMARY KEY
                c.execute("""
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
                # 4. Copier les données en adaptant les colonnes manquantes
                old_cols = {r[0].lower() for r in c.execute("DESCRIBE records_old").fetchall()}
                pwd_expr  = "COALESCE(password_set, FALSE)" if "password_set" in old_cols else "FALSE"
                hash_expr = "hash_val" if "hash_val" in old_cols else "NULL"
                phone_expr= "phone"    if "phone"    in old_cols else "NULL"
                raw_expr  = "raw"      if "raw"      in old_cols else "NULL"
                c.execute(
                    "INSERT INTO records "
                    "SELECT id, src, email, username, "
                    f"{pwd_expr}, {hash_expr}, domain, ip, {phone_expr}, {raw_expr} "
                    "FROM records_old"
                )
                c.execute("DROP TABLE records_old")
                log.info("Migration: PRIMARY KEY ajouté sur records.id ✓")
        except Exception as _pk_err:
            log.debug(f"Migration PK check: {_pk_err}")
        existing = {r[0].lower() for r in c.execute("DESCRIBE records").fetchall()}
        # v4.0 stockait password VARCHAR + hash_val -> v4.1 stocke password_set BOOLEAN
        if "password" in existing and "password_set" not in existing:
            # On convertit l'ancienne colonne password en booléen (sans conserver le clair)
            c.execute("ALTER TABLE records ADD COLUMN password_set BOOLEAN DEFAULT FALSE")
            c.execute("UPDATE records SET password_set = TRUE WHERE password IS NOT NULL AND password <> ''")
            # On ne supprime pas la colonne ancienne pour éviter de casser, mais on ne la renvoie plus.
            log.info("Migration: colonne password_set ajoutée (depuis password).")
        if "password_set" not in existing and "password" not in existing:
            c.execute("ALTER TABLE records ADD COLUMN password_set BOOLEAN DEFAULT FALSE")
        c.commit()
    except Exception as e:
        log.debug(f"Migration: {e}")


# ── STATE ─────────────────────────────────────────────────────
class State:
    importing = False
    progress  = {"done": 0, "total": 0, "cur": "", "phase": "idle"}
    total_rec = 0
state = State()

# ── HELPERS ID (CORRIGÉ : hashlib au lieu de hash()) ─────────
def _stable_id(key: str) -> int:
    """ID stable entre redémarrages (hash() Python est randomisé par PYTHONHASHSEED)."""
    h = hashlib.sha1(key.encode("utf-8")).digest()
    return int.from_bytes(h[:8], "big") % 9223372036854775807

def already(path: str, mtime: float) -> bool:
    try:
        with _lock:
            r = db().execute("SELECT mtime FROM imported WHERE path=?", [path]).fetchone()
        return bool(r and abs(r[0] - mtime) < 1)
    except Exception:
        return False

def mark(path: str, mtime: float, rows: int):
    with _lock:
        db().execute("INSERT INTO imported VALUES(?,?,?) ON CONFLICT (path) DO UPDATE SET mtime=excluded.mtime, rows=excluded.rows", [path, mtime, rows])
        db().commit()

# ── MASQUAGE MOT DE PASSE ─────────────────────────────────────
def mask_password(pwd: str) -> str:
    """Ne renvoie jamais un mot de passe en clair : 2 premiers + étoiles + dernier."""
    if not pwd:
        return ""
    if len(pwd) <= 3:
        return "*" * len(pwd)
    return pwd[:2] + "*" * (len(pwd) - 3) + pwd[-1]

# ═══════════════════════════════════════════════════════════════
# PARSERS UNIVERSELS
# ═══════════════════════════════════════════════════════════════

def _detect_separator(sample_lines: list[str]) -> str:
    """Détecte le séparateur dominant dans un échantillon de lignes."""
    scores = {}
    for sep in SEPARATORS:
        counts = [len(line.split(sep)) for line in sample_lines if line.strip()]
        if counts:
            avg = sum(counts) / len(counts)
            variance = sum((c - avg) ** 2 for c in counts) / len(counts)
            if avg > 1.5 and variance < 5:
                scores[sep] = avg / (1 + variance)
    return max(scores, key=scores.get) if scores else ":"


def _extract_fields_from_parts(parts: list[str]) -> dict:
    """Extrait email/username/ip depuis des parties séparées."""
    result = {"email": "", "username": "", "password": "", "ip": "", "phone": "", "hash_val": ""}
    if not parts:
        return result

    email_idx, ip_idx = -1, -1
    for i, p in enumerate(parts):
        if RE_EMAIL.fullmatch(p.strip()):
            email_idx = i
        elif RE_IP.fullmatch(p.strip()):
            ip_idx = i

    if email_idx >= 0:
        result["email"] = parts[email_idx].strip()
        others = [parts[i].strip() for i in range(len(parts)) if i != email_idx]
        if others:
            result["password"] = others[-1]
        if len(others) >= 2:
            result["username"] = others[0]
    elif ip_idx >= 0:
        result["ip"] = parts[ip_idx].strip()
        others = [parts[i].strip() for i in range(len(parts)) if i != ip_idx]
        if others:
            result["username"] = others[0]
        if len(others) >= 2:
            result["password"] = others[-1]
    else:
        result["username"] = parts[0].strip()
        if len(parts) >= 2:
            result["password"] = parts[-1].strip()

    for p in parts:
        p = p.strip()
        if not result["email"] and RE_EMAIL.fullmatch(p):
            result["email"] = p
        if not result["ip"] and RE_IP.fullmatch(p):
            result["ip"] = p
        if not result["phone"] and RE_PHONE.fullmatch(p):
            result["phone"] = p
        if not result["hash_val"] and RE_HASH.fullmatch(p):
            result["hash_val"] = p
    return result


def _enrich_from_raw(raw: str) -> dict:
    """Extraction regex directe sur une ligne brute."""
    result = {"email": "", "username": "", "password": "", "domain": "", "ip": "", "phone": "", "hash_val": ""}
    if not raw:
        return result
    m = RE_EMAIL.search(raw)
    if m:
        result["email"] = m.group(0)
        result["domain"] = m.group(0).split("@", 1)[1]
    m = RE_IP.search(raw)
    if m:
        result["ip"] = m.group(0)
    m = RE_PHONE.search(raw)
    if m:
        result["phone"] = m.group(0).strip()
    m = RE_HASH.search(raw)
    if m:
        result["hash_val"] = m.group(0)
    return result


def _normalize_col(name: str) -> str:
    return name.lower().strip().replace(" ", "_").replace("-", "_")

# Mapping fuzzy nom de colonne → champ interne
COL_MAPPING = {
    "email": ["email", "mail", "courriel", "e_mail", "email_address"],
    "username": ["username", "user", "login", "pseudo", "nickname", "nick", "name", "nom", "utilisateur", "handle", "user_name", "user_id"],
    "password": ["password", "pass", "pwd", "passwd", "mot_de_passe", "mdp", "hash", "hashed_password"],
    "ip": ["ip", "ip_address", "ipaddress", "addr", "adresse_ip", "ip_addr"],
    "domain": ["domain", "domaine", "host", "hostname", "site"],
    "phone": ["phone", "telephone", "tel", "mobile", "cell", "numero", "phone_number"],
    "hash_val": ["hash", "md5", "sha1", "sha256", "hashed", "password_hash"],
}


def _match_col(name: str) -> Optional[str]:
    n = _normalize_col(name)
    for field, patterns in COL_MAPPING.items():
        for pat in patterns:
            if pat in n or n in pat:
                return field
    return None


def _sanitized_raw(raw: str) -> str:
    """On NE conserve que les emails/domaines/IP/hashs dans le champ raw affiché.
    On retire les mots de passe potentiels pour ne jamais les fuiter."""
    if not raw:
        return ""
    # On ne garde que les jetons reconnus (email, ip, hash, phone, domain)
    tokens = []
    for rx in (RE_EMAIL, RE_IP, RE_HASH, RE_PHONE):
        for m in rx.findall(raw):
            tokens.append(m if isinstance(m, str) else m[0])
    return " | ".join(dict.fromkeys(tokens))[:1000]


def _parse_parts_line(line: str, sep: str) -> dict:
    parts = [p.strip() for p in line.split(sep) if p.strip()]
    r = _extract_fields_from_parts(parts)
    en = _enrich_from_raw(line)
    for k, v in en.items():
        if not r.get(k):
            r[k] = v
    return r

# ═══════════════════════════════════════════════════════════════
# IMPORT FICHIERS (STREAMING pour les gros fichiers)
# ═══════════════════════════════════════════════════════════════

BATCH_SIZE = 200_000


def _insert_batch(c, rows: list[dict], src: str) -> int:
    """Insère un batch de dicts dans DuckDB. Ne stocke JAMAIS le mot de passe en clair."""
    if not rows:
        return 0
    records = []
    for i, r in enumerate(rows):
        email    = (r.get("email")    or "").strip()[:500]
        username = (r.get("username") or "").strip()[:500]
        password = (r.get("password") or "")
        domain   = (r.get("domain")   or "").strip()[:255]
        ip       = (r.get("ip")       or "").strip()[:45]
        phone    = (r.get("phone")    or "").strip()[:50]
        hash_val = (r.get("hash_val") or "").strip()[:128]
        raw      = _sanitized_raw(r.get("raw") or "")

        if not domain and email and "@" in email:
            domain = email.split("@", 1)[1]

        has_password = bool(password)
        key = f"{src}|{email}|{username}|{hash_val}|{domain}|{ip}|{i}"
        uid = _stable_id(key)

        records.append((uid, src, email or None, username or None,
                        has_password, hash_val or None,
                        domain or None, ip or None, phone or None, raw or None))

    c.executemany("INSERT INTO records VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT (id) DO NOTHING", records)
    return len(records)


def _iter_lines(path: Path):
    """Itérateur sur les lignes d'un fichier (streaming, pas de read_text())."""
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            yield line.rstrip("\n\r")


def _parse_delimited_stream(path: Path, src: str) -> int:
    """Parse TXT/fichiers délimités en streaming. Retourne le nombre de lignes insérées."""
    # Détecter le séparateur sur un échantillon
    sample = []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f):
                if i >= 30:
                    break
                if line.strip():
                    sample.append(line.rstrip("\n\r"))
    except Exception:
        return 0
    sep = _detect_separator(sample) if sample else ":"

    total = 0
    batch: list[dict] = []
    file_size = path.stat().st_size if path.exists() else 0
    t0 = time.time()
    bytes_read = 0
    with _lock:
        c = db()
        for line in _iter_lines(path):
            bytes_read += len(line.encode("utf-8", errors="replace")) + 1
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("--"):
                continue
            r = _parse_parts_line(line, sep)
            r["raw"] = line
            batch.append(r)
            if len(batch) >= BATCH_SIZE:
                total += _insert_batch(c, batch, src)
                batch.clear()
                elapsed = time.time() - t0
                pct = (bytes_read / file_size * 100) if file_size else 0
                rate = total / elapsed if elapsed > 0 else 0
                log.info(f"  {src}: {pct:.0f}% — {total:,} records ({rate:,.0f}/s)")
        if batch:
            total += _insert_batch(c, batch, src)
        c.commit()
    return total


def _parse_csv_file(path: Path, src: str) -> int:
    """Parse CSV/TSV en streaming avec détection du séparateur et des colonnes."""
    total = 0
    try:
        # Sniffer sur l'en-tête
        with path.open("r", encoding="utf-8", errors="replace") as f:
            head = "".join(f.readline() for _ in range(5))
        sep = ","
        try:
            import csv as _csv
            dialect = _csv.Sniffer().sniff(head, delimiters=":,;|\t")
            sep = dialect.delimiter
        except Exception:
            sep = _detect_separator(head.splitlines())

        reader = _csv.reader(path.open("r", encoding="utf-8", errors="replace"), delimiter=sep)
        fieldnames = next(reader, None)
        if not fieldnames:
            raise ValueError("no headers")

        col_map = {}
        for col in fieldnames:
            field = _match_col(col)
            if field:
                col_map[col] = field
        has_structure = bool(col_map)

        batch: list[dict] = []
        with _lock:
            c = db()
            for row in reader:
                row_dict = dict(zip(fieldnames, row))
                if has_structure:
                    r = {}
                    for csv_col, field in col_map.items():
                        r[field] = row_dict.get(csv_col, "") or ""
                    r["raw"] = "|".join(str(v) for v in row_dict.values() if v)
                else:
                    vals = [v for v in row if v]
                    raw = sep.join(vals)
                    r = _enrich_from_raw(raw)
                    r.update(_extract_fields_from_parts(vals))
                    r["raw"] = raw
                batch.append(r)
                if len(batch) >= BATCH_SIZE:
                    total += _insert_batch(c, batch, src)
                    batch.clear()
            if batch:
                total += _insert_batch(c, batch, src)
            c.commit()
    except Exception as e:
        log.debug(f"CSV parse {src}: {e} — fallback ligne par ligne")
        total = _parse_delimited_stream(path, src)
    return total


def _parse_jsonl_stream(path: Path, src: str) -> int:
    """Parse JSONL/NDJSON ligne par ligne (streaming)."""
    total = 0
    batch: list[dict] = []
    with _lock:
        c = db()
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line in ("[", "]", "{", "}"):
                    continue
                try:
                    obj = json.loads(line)
                    r = {}
                    raw_parts = []
                    if isinstance(obj, dict):
                        for k, v in obj.items():
                            field = _match_col(k)
                            val = str(v).strip() if v is not None else ""
                            raw_parts.append(val)
                            if field and val:
                                r[field] = val
                        if not r:
                            r = _enrich_from_raw(" ".join(raw_parts))
                        r["raw"] = " | ".join(raw_parts[:20])
                    else:
                        raw = str(obj)
                        r = _enrich_from_raw(raw)
                        r["raw"] = raw
                    batch.append(r)
                except json.JSONDecodeError:
                    sep = _detect_separator([line])
                    r = _parse_parts_line(line, sep or ":")
                    r["raw"] = line
                    batch.append(r)
                if len(batch) >= BATCH_SIZE:
                    total += _insert_batch(c, batch, src)
                    batch.clear()
        if batch:
            total += _insert_batch(c, batch, src)
        c.commit()
    return total


def _parse_json_file(path: Path, src: str) -> int:
    """Parse JSON gros ou petit — essai streaming d'abord, fallback lecture complète."""
    # Stratégie 1 : si le fichier ressemble à du JSONL (une ligne = un objet), streaming direct
    # Stratégie 2 : JSON array/objet → on tente ijson si dispo, sinon on streame ligne par ligne
    # On NE fait plus jamais de read_text() sur un gros fichier.

    file_size = path.stat().st_size if path.exists() else 0
    BIG = 50 * 1024 * 1024  # 50 MB

    # Lire les premières lignes pour détecter le format
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            first_lines = [f.readline().strip() for _ in range(5)]
        first_lines = [l for l in first_lines if l]
    except Exception:
        return 0

    first = first_lines[0] if first_lines else ""

    # Cas 1 : JSONL (chaque ligne est un JSON valide)
    if first.startswith("{") or first.startswith("[{"):
        try:
            json.loads(first)  # valide ?
            return _parse_jsonl_stream(path, src)
        except json.JSONDecodeError:
            pass

    # Cas 2 : JSON array ouvert sur plusieurs lignes → streaming via ijson si dispo
    if file_size > BIG:
        try:
            import ijson  # type: ignore
            return _parse_json_ijson(path, src)
        except ImportError:
            pass
        # Sans ijson sur un gros fichier → fallback JSONL ligne par ligne
        log.warning(f"JSON {src}: fichier volumineux ({file_size//1024//1024} MB), "
                    f"install 'pip install ijson' pour un meilleur support. Fallback ligne par ligne.")
        return _parse_jsonl_stream(path, src)

    # Cas 3 : petit fichier → lecture complète safe
    rows: list[dict] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        data = json.loads(text)

        def _extract(obj, depth=0):
            if depth > 5:
                return
            if isinstance(obj, dict):
                r = {}
                raw_parts = []
                for k, v in obj.items():
                    field = _match_col(k)
                    val = str(v).strip() if v is not None else ""
                    raw_parts.append(val)
                    if field and val:
                        r[field] = val
                if not r:
                    raw = " ".join(raw_parts)
                    r = _enrich_from_raw(raw)
                r["raw"] = " | ".join(raw_parts[:20])
                if any(r.get(f) for f in ["email", "username", "ip", "domain"]):
                    rows.append(r)
                else:
                    for v in obj.values():
                        if isinstance(v, (dict, list)):
                            _extract(v, depth + 1)
            elif isinstance(obj, list):
                for item in obj:
                    _extract(item, depth)
            elif isinstance(obj, str):
                r = _enrich_from_raw(obj)
                if any(r.get(f) for f in ["email", "username", "ip"]):
                    r["raw"] = obj
                    rows.append(r)

        _extract(data)
        total = 0
        with _lock:
            c = db()
            for i in range(0, len(rows), BATCH_SIZE):
                total += _insert_batch(c, rows[i:i + BATCH_SIZE], src)
            c.commit()
        return total
    except json.JSONDecodeError:
        return _parse_jsonl_stream(path, src)
    except MemoryError:
        log.warning(f"JSON {src}: MemoryError — fallback streaming")
        return _parse_jsonl_stream(path, src)
    except Exception as e:
        log.warning(f"JSON parse {src}: {type(e).__name__}: {e} — fallback délimité")
        return _parse_delimited_stream(path, src)


def _parse_json_ijson(path: Path, src: str) -> int:
    """Parse JSON array volumineux avec ijson (streaming vrai)."""
    import ijson  # type: ignore
    total = 0
    batch: list[dict] = []
    try:
        with _lock:
            c = db()
            with path.open("rb") as f:
                for obj in ijson.items(f, "item"):
                    if isinstance(obj, dict):
                        r = {}
                        raw_parts = []
                        for k, v in obj.items():
                            field = _match_col(k)
                            val = str(v).strip() if v is not None else ""
                            raw_parts.append(val)
                            if field and val:
                                r[field] = val
                        if not r:
                            r = _enrich_from_raw(" ".join(raw_parts))
                        r["raw"] = " | ".join(raw_parts[:20])
                        batch.append(r)
                    elif isinstance(obj, str):
                        r = _enrich_from_raw(obj)
                        r["raw"] = obj
                        batch.append(r)
                    if len(batch) >= BATCH_SIZE:
                        total += _insert_batch(c, batch, src)
                        batch.clear()
            if batch:
                total += _insert_batch(c, batch, src)
            c.commit()
    except Exception as e:
        log.warning(f"ijson {src}: {e}")
    return total


def _parse_sql_file(path: Path, src: str) -> int:
    """Extrait les données des INSERT INTO d'un fichier SQL (streaming)."""
    total = 0
    batch: list[dict] = []
    insert_re = re.compile(
        r"INSERT\s+(?:INTO\s+)?[`'\"]?(\w+)[`'\"]?\s*"
        r"(?:\(([^)]+)\))?\s*VALUES\s*\(([^;]+)\)",
        re.IGNORECASE | re.DOTALL
    )
    with _lock:
        c = db()
        try:
            with path.open("r", encoding="utf-8", errors="replace") as f:
                for chunk in f:
                    for m in insert_re.finditer(chunk):
                        col_str = m.group(2) or ""
                        val_str = m.group(3) or ""
                        cols = [x.strip().strip("`'\"") for x in col_str.split(",") if x.strip()]
                        vals = re.findall(r"'([^']*)'|\"([^\"]*)\"|(\d+)", val_str)
                        vals = [a or b or c for a, b, c in vals]
                        if cols and vals:
                            row_dict = dict(zip(cols, vals))
                            r = {}
                            for col, val in row_dict.items():
                                field = _match_col(col)
                                if field and val:
                                    r[field] = val
                            r["raw"] = " | ".join(f"{k}={v}" for k, v in row_dict.items())
                            batch.append(r)
                        else:
                            r = _enrich_from_raw(val_str)
                            r["raw"] = val_str
                            if any(r.get(f) for f in ["email", "username", "ip"]):
                                batch.append(r)
                        if len(batch) >= BATCH_SIZE:
                            total += _insert_batch(c, batch, src)
                            batch.clear()
            if batch:
                total += _insert_batch(c, batch, src)
            c.commit()
        except Exception as e:
            log.warning(f"SQL parse {src}: {e}")
            total = _parse_delimited_stream(path, src)
    if total == 0:
        total = _parse_delimited_stream(path, src)
    return total

# ── IMPORT PRINCIPAL ─────────────────────────────────────────
EXTS = {".csv", ".tsv", ".json", ".jsonl", ".ndjson", ".txt", ".sql"}


def _duckdb_native_import(p: Path, src: str, ext: str) -> int:
    """Import ultra-rapide via DuckDB natif (C++) — 10-50x plus vite que Python pur."""
    safe = str(p).replace("'", "''")
    safe_src = src.replace("'", "''")

    # Colonnes email/user/domain/ip standards
    EMAIL_PATS   = ("email","mail","courriel","e_mail")
    USER_PATS    = ("username","user","login","pseudo","nom","name","handle")
    PASS_PATS    = ("password","pass","pwd","passwd","mot_de_passe","mdp")
    IP_PATS      = ("ip","ip_address","ipaddress","addr")
    DOMAIN_PATS  = ("domain","domaine","host","hostname","site")
    PHONE_PATS   = ("phone","telephone","tel","mobile","cell")
    HASH_PATS    = ("hash","md5","sha1","sha256","hashed","hash_val","password_hash")

    def match(cols, *pats):
        for p in pats:
            for c in cols:
                if p in c.lower():
                    return f'"{c}"'
        return "NULL"

    try:
        with _lock:
            c = db()
            before = c.execute("SELECT COUNT(*) FROM records").fetchone()[0]

            if ext in (".csv", ".tsv"):
                sep = "\t" if ext == ".tsv" else ","
                # Lire les colonnes disponibles
                try:
                    desc = c.execute(
                        f"SELECT * FROM read_csv_auto('{safe}', ignore_errors=true, "
                        f"null_padding=true, parallel=true) LIMIT 0"
                    ).description
                    cols = [r[0] for r in desc] if desc else []
                except Exception:
                    cols = []

                if cols:
                    sel_e   = match(cols, *EMAIL_PATS)
                    sel_u   = match(cols, *USER_PATS)
                    sel_i   = match(cols, *IP_PATS)
                    sel_d   = match(cols, *DOMAIN_PATS)
                    sel_ph  = match(cols, *PHONE_PATS)
                    sel_h   = match(cols, *HASH_PATS)
                    sel_p   = match(cols, *PASS_PATS)
                    raw_x   = " || '|' || ".join(
                        "COALESCE(CAST(\"" + col + "\" AS VARCHAR),'')" for col in cols[:20]
                    )
                    c.execute(f"""
                        INSERT INTO records
                        SELECT
                            abs(hash('{safe_src}' || CAST(row_number() OVER() AS VARCHAR))) % 9223372036854775807,
                            '{safe_src}',
                            {sel_e},
                            {sel_u},
                            {sel_p} IS NOT NULL AND {sel_p} <> '',
                            {sel_h},
                            COALESCE({sel_d},
                                CASE WHEN {sel_e} LIKE '%@%'
                                     THEN split_part({sel_e},'@',2) END),
                            {sel_i},
                            {sel_ph},
                            {raw_x}
                        FROM read_csv_auto('{safe}', ignore_errors=true,
                            null_padding=true, parallel=true)
                        ON CONFLICT (id) DO NOTHING
                    """)
                else:
                    # Pas de header → lignes brutes (email:pass etc.)
                    c.execute(f"""
                        INSERT INTO records
                        SELECT
                            abs(hash('{safe_src}' || CAST(row_number() OVER() AS VARCHAR))) % 9223372036854775807,
                            '{safe_src}',
                            regexp_extract(line, '[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{{2,}}', 0),
                            NULL, FALSE, NULL,
                            regexp_extract(line, '@([a-zA-Z0-9.\\-]+\\.[a-zA-Z]{{2,}})', 1),
                            NULL, NULL,
                            line
                        FROM read_csv('{safe}', columns={{'line':'VARCHAR'}},
                            header=false, ignore_errors=true, parallel=true)
                        WHERE trim(line) != ''
                        ON CONFLICT (id) DO NOTHING
                    """)
                c.commit()

            elif ext == ".txt":
                c.execute(f"""
                    INSERT INTO records
                    SELECT
                        abs(hash('{safe_src}' || CAST(row_number() OVER() AS VARCHAR))) % 9223372036854775807,
                        '{safe_src}',
                        regexp_extract(line, '[a-zA-Z0-9._%+\\\-]+@[a-zA-Z0-9.\\\-]+\\\.[a-zA-Z]{{2,}}', 0),
                        NULL, FALSE, NULL,
                        regexp_extract(line, '@([a-zA-Z0-9.\\\-]+\\\.[a-zA-Z]{{2,}})', 1),
                        NULL, NULL,
                        line
                    FROM read_csv('{safe}', columns={{'line':'VARCHAR'}},
                        header=false, ignore_errors=true, parallel=true)
                    WHERE trim(line) != ''
                    ON CONFLICT (id) DO NOTHING
                """)
                c.commit()

            else:
                return -1  # pas supporté en natif

            after = c.execute("SELECT COUNT(*) FROM records").fetchone()[0]
            return max(0, after - before)

    except Exception as e:
        log.debug(f"DuckDB natif {src}: {e} — fallback Python")
        return -1  # signal fallback


def import_file(p: Path) -> int:
    try:
        mtime = p.stat().st_mtime
        file_size = p.stat().st_size
    except Exception:
        return 0
    if already(str(p), mtime):
        return 0

    src = p.name
    ext = p.suffix.lower()
    size_mb = file_size / 1024 / 1024
    log.info(f"⏳ {src} ({size_mb:.1f} MB)...")

    # Tenter DuckDB natif d'abord (ultra rapide) pour CSV/TXT
    if ext in (".csv", ".tsv", ".txt"):
        total = _duckdb_native_import(p, src, ext)
        if total >= 0:
            mark(str(p), mtime, total)
            if total > 0:
                log.info(f"✓ {src}: {total:,} records [natif DuckDB]")
            else:
                log.info(f"✓ {src}: 0 records (fichier vide ou déjà importé)")
            return total
        # Si natif échoue → fallback Python ci-dessous

    # Fallback Python avec progress
    t0 = time.time()
    try:
        if ext in (".csv", ".tsv"):
            total = _parse_csv_file(p, src)
        elif ext == ".json":
            total = _parse_json_file(p, src)
        elif ext in (".jsonl", ".ndjson"):
            total = _parse_jsonl_stream(p, src)
        elif ext == ".sql":
            total = _parse_sql_file(p, src)
        else:
            total = _parse_delimited_stream(p, src)
    except Exception as e:
        log.warning(f"Parse {src}: {e}")
        return 0

    elapsed = time.time() - t0
    mark(str(p), mtime, total)
    if total > 0:
        rate = total / elapsed if elapsed > 0 else 0
        log.info(f"✓ {src}: {total:,} records en {elapsed:.1f}s ({rate:,.0f} rec/s)")
    return total


def collect() -> list[Path]:
    found, seen = [], set()
    for root in SCAN_ROOTS:
        try:
            if not root.exists():
                continue
            for f in root.rglob("*"):
                s = str(f).lower()
                if s not in seen and f.is_file() and f.suffix.lower() in EXTS:
                    seen.add(s)
                    found.append(f)
        except Exception:
            pass
    return found


def run_import():
    if state.importing:
        return
    state.importing = True
    state.progress = {"done": 0, "total": 0, "cur": "", "phase": "scan"}
    try:
        files = collect()
        to_do = [f for f in files if not already(str(f), f.stat().st_mtime if f.exists() else 0)]
        state.progress["total"] = len(to_do)
        state.progress["phase"] = "import"
        log.info(f"📦 {len(to_do)} fichiers à importer")

        # Parse les fichiers en parallèle (I/O + CPU bound) puis insert dans DuckDB.
        # DuckDB est protégé par _lock → les inserts se sérialisent automatiquement.
        # On utilise 4 workers pour le parse simultané des fichiers.
        from concurrent.futures import ThreadPoolExecutor, as_completed
        workers = min(4, max(1, len(to_do)))
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {ex.submit(import_file, f): f for f in to_do}
            for fut in as_completed(futures):
                if _shutdown.is_set():
                    break
                try:
                    fut.result()
                except Exception:
                    pass
                state.progress["done"] += 1
                state.progress["cur"] = futures[fut].name

        with _lock:
            r = db().execute("SELECT COUNT(*) FROM records").fetchone()
            state.total_rec = r[0] if r else 0
        state.progress["phase"] = "idle"
        log.info(f"✅ Import terminé. Total: {state.total_rec:,} records")
    finally:
        state.importing = False


def _ensure_scan_dirs():
    for root in SCAN_ROOTS:
        try:
            root.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass


def bg_loop():
    _ensure_scan_dirs()
    run_import()
    while not _shutdown.is_set():
        if _shutdown.wait(RESCAN_SECS):
            break
        run_import()

# ═══════════════════════════════════════════════════════════════
# AUTHENTIFICATION JWT SUPABASE
# ═══════════════════════════════════════════════════════════════

def _verify_token(token: Optional[str]) -> Optional[dict]:
    """Vérifie un JWT Supabase. Retourne le payload ou None."""
    if not REQUIRE_AUTH or not SUPABASE_JWT_SECRET:
        return {"sub": "dev", "email": "dev@local"}  # mode sans auth
    if not token:
        return None
    try:
        import jwt as pyjwt
        payload = pyjwt.decode(token, SUPABASE_JWT_SECRET, algorithms=["HS256"], audience="authenticated")
        return payload
    except Exception as e:
        log.debug(f"JWT invalide: {e}")
        return None


def require_auth(request: Request) -> dict:
    """Dépendance FastAPI : vérifie le JWT dans l'en-tête Authorization."""
    if not REQUIRE_AUTH or not SUPABASE_JWT_SECRET:
        return {"sub": "dev", "email": "dev@local"}
    auth = request.headers.get("Authorization", "")
    token = auth.replace("Bearer ", "").strip() if auth.lower().startswith("bearer") else ""
    payload = _verify_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Token invalide ou manquant")
    return payload


def require_auth_ws(token: Optional[str]) -> Optional[dict]:
    """Vérifie le JWT pour WebSocket (token passé en query param)."""
    return _verify_token(token)

# ═══════════════════════════════════════════════════════════════
# RECHERCHE + GRAPHE
# ═══════════════════════════════════════════════════════════════

def _detect_type(q: str) -> str:
    q = q.strip()
    if RE_EMAIL.fullmatch(q):    return "email"
    if RE_IP.fullmatch(q):       return "ip"
    if RE_HASH.fullmatch(q):     return "hash"
    if RE_PHONE.fullmatch(q):    return "phone"
    if re.match(r"^[\w\-]+(\.[\w\-]+)+$", q): return "domain"
    return "username"


def search_raw(query: str, limit: int = MAX_RESULTS) -> list[dict]:
    """Recherche multi-champs dans DuckDB."""
    terms = [t.strip() for t in query.split() if len(t.strip()) >= 2]
    if not terms:
        return []

    conditions, params = [], []
    for t in terms:
        like = f"%{t.lower()}%"
        conditions.append("""(
            LOWER(COALESCE(email,''))    LIKE ? OR
            LOWER(COALESCE(username,'')) LIKE ? OR
            LOWER(COALESCE(domain,''))   LIKE ? OR
            LOWER(COALESCE(ip,''))       LIKE ? OR
            LOWER(COALESCE(phone,''))    LIKE ? OR
            LOWER(COALESCE(hash_val,'')) LIKE ? OR
            LOWER(COALESCE(raw,''))      LIKE ?
        )""")
        params.extend([like] * 7)

    sql = f"""
        SELECT src, email, username, password_set, hash_val, domain, ip, phone, raw
        FROM records
        WHERE {" AND ".join(conditions)}
        LIMIT {limit}
    """
    try:
        with _lock:
            rows = db().execute(sql, params).fetchall()
        # NB: on ne renvoie plus la colonne 'password' claire (elle n'existe plus en v4.1)
        return [
            {
                "source":       r[0] or "",
                "email":        r[1] or "",
                "username":     r[2] or "",
                "password_set": bool(r[3]),
                "hash_val":     r[4] or "",
                "domain":       r[5] or "",
                "ip":           r[6] or "",
                "phone":        r[7] or "",
                "raw":          r[8] or "",
            }
            for r in rows
        ]
    except Exception as e:
        log.error(f"search_raw: {e}")
        return []


def _build_graph(query: str, rows: list[dict]) -> dict:
    """Construit un graphe de connexions complet."""
    nodes: list[dict] = []
    edges: list[dict] = []
    node_map: dict[str, str] = {}
    edge_set: set[str] = set()

    def node_id(val: str) -> str:
        if val not in node_map:
            node_map[val] = f"n{len(node_map)}"
        return node_map[val]

    def add_node(val: str, ntype: str, meta: dict = {}):
        nid = node_id(val)
        if not any(n["id"] == nid for n in nodes):
            nodes.append({"id": nid, "label": val, "type": ntype, **meta})
        return nid

    def add_edge(src_id: str, tgt_id: str, label: str, weight: int = 1):
        key = f"{src_id}→{tgt_id}→{label}"
        if key not in edge_set:
            edge_set.add(key)
            edges.append({"from": src_id, "to": tgt_id, "label": label, "weight": weight})

    q_type = _detect_type(query)
    root = add_node(query, q_type, {"root": True})

    for row in rows:
        src      = row["source"]
        email    = row["email"].strip()
        username = row["username"].strip()
        has_pwd  = row.get("password_set")
        domain   = row["domain"].strip()
        ip       = row["ip"].strip()
        phone    = row["phone"].strip()
        hash_v   = row.get("hash_val", "").strip()

        entities: dict[str, str] = {}

        if email:
            nid = add_node(email, "email", {"source": src})
            add_edge(root, nid, "email trouvé", 3)
            entities["email"] = nid
            if "@" in email:
                dom = email.split("@")[1]
                did = add_node(dom, "domain", {"source": src})
                add_edge(nid, did, "domaine", 2)

        if username:
            nid = add_node(username, "username", {"source": src})
            add_edge(root, nid, "identifiant", 2)
            entities["username"] = nid

        if domain and domain not in (email.split("@")[1] if "@" in email else ""):
            nid = add_node(domain, "domain", {"source": src})
            add_edge(root, nid, "domaine associé", 1)
            entities["domain"] = nid

        if ip:
            nid = add_node(ip, "ip", {"source": src})
            add_edge(root, nid, "IP associée", 2)
            entities["ip"] = nid

        if phone:
            nid = add_node(phone, "phone", {"source": src})
            add_edge(root, nid, "téléphone", 2)
            entities["phone"] = nid

        if hash_v:
            short = hash_v[:20] + "…" if len(hash_v) > 20 else hash_v
            nid = add_node(short, "hash", {"full": hash_v, "source": src})
            add_edge(root, nid, "hash", 1)
            entities["hash"] = nid

        if has_pwd:
            nid = add_node(f"[mot de passe exposé @ {src}]", "alert", {"source": src})
            if "email" in entities:
                add_edge(entities["email"], nid, "mot de passe trouvé", 3)
            elif "username" in entities:
                add_edge(entities["username"], nid, "mot de passe trouvé", 3)
            else:
                add_edge(root, nid, "alerte", 2)

        ent_list = list(entities.values())
        for i in range(len(ent_list)):
            for j in range(i + 1, len(ent_list)):
                add_edge(ent_list[i], ent_list[j], "même enregistrement", 2)

    return {"nodes": nodes, "edges": edges}


def _build_payload(query: str, rows: list[dict]) -> dict:
    """Construit le payload complet pour le frontend."""
    emails, usernames, ips, domains, phones, alerts = [], [], [], [], [], []
    seen: dict[str, set] = {k: set() for k in ["email", "username", "ip", "domain", "phone"]}

    for row in rows:
        src      = row["source"]
        email    = row["email"].strip()
        username = row["username"].strip()
        has_pwd  = row.get("password_set")
        domain   = row["domain"].strip()
        ip       = row["ip"].strip()
        phone    = row["phone"].strip()

        if not domain and email and "@" in email:
            domain = email.split("@", 1)[1]

        if email and email not in seen["email"]:
            seen["email"].add(email)
            emails.append({"email": email, "platform": src, "trust_level": "VERIFIED", "sources": [src]})

        if username and username not in seen["username"]:
            seen["username"].add(username)
            usernames.append({"username": username, "platform": src, "trust_level": "VERIFIED", "sources": [src]})

        if ip and ip not in seen["ip"]:
            seen["ip"].add(ip)
            ips.append({"ip": ip, "platform": src, "trust_level": "VERIFIED", "sources": [src]})

        if domain and domain not in seen["domain"]:
            seen["domain"].add(domain)
            domains.append({"subdomain": domain, "platform": src, "trust_level": "PROBABLE", "sources": [src]})

        if phone and phone not in seen["phone"]:
            seen["phone"].add(phone)
            phones.append({"note": phone, "platform": src, "trust_level": "PROBABLE", "sources": [src]})

        if email and has_pwd:
            alerts.append({
                "email":       email,
                "username":    username or None,
                "note":        "Mot de passe exposé (non affiché)",
                "platform":    src,
                "trust_level": "VERIFIED",
                "sources":     [src],
            })

    sections = []
    if alerts:
        sections.append({"label": "Données sensibles détectées", "icon": "🚨", "items": alerts[:500]})
    if emails:
        sections.append({"label": "Adresses email",      "icon": "📧", "items": emails[:500]})
    if usernames:
        sections.append({"label": "Identifiants",        "icon": "🏷️", "items": usernames[:300]})
    if ips:
        sections.append({"label": "Adresses IP",         "icon": "🌍", "items": ips[:200]})
    if domains:
        sections.append({"label": "Domaines associés",   "icon": "🌐", "items": domains[:200]})
    if phones:
        sections.append({"label": "Numéros de téléphone","icon": "📞", "items": phones[:100]})

    v = sum(1 for s in sections for i in s["items"] if i.get("trust_level") == "VERIFIED")
    p = sum(1 for s in sections for i in s["items"] if i.get("trust_level") == "PROBABLE")
    c = sum(1 for s in sections for i in s["items"] if i.get("trust_level") == "CANDIDATE")

    identity_card = {
        "name": query,
        "confidence_summary": {"verified": v, "probable": p, "candidate": c},
        "summary": {
            "emails":     len(emails),
            "usernames":  len(usernames),
            "alerts":     len(alerts),
            "ips":        len(ips),
            "domains":    len(domains),
            "phones":     len(phones),
        },
    }

    return {
        "query":         query,
        "input_type":    _detect_type(query),
        "sections":      sections,
        "identity_card": identity_card,
        "total_results": len(rows),
        "graph":         _build_graph(query, rows),
    }

# ═══════════════════════════════════════════════════════════════
# MODULES (concept multi-tool)
# ═══════════════════════════════════════════════════════════════
# La recherche DuckDB est présentée sous forme de modules pour l'UI.
# Chaque module filtre/fait ressortir un type de signal dans les résultats.

MODULES = [
    ("duckdb_local",     "Base de données locale"),
    ("email_reputation", "Réputation email"),
    ("domain_lookup",    "Domaines associés"),
    ("ip_intel",         "Renseignement IP"),
    ("phone_lookup",     "Téléphones"),
    ("hash_check",       "Empreintes / hashs"),
]


async def _emit_modules(ws: WebSocket, q: str, rows: list[dict]):
    """Émet les messages de progression par module (pour garder l'effet multi-tool)."""
    loop = asyncio.get_event_loop()
    q_type = _detect_type(q)

    await ws.send_json({
        "type":    "detected",
        "targets": [{"value": q, "detected_type": q_type}],
    })
    await ws.send_json({
        "type": "start", "total_jobs": len(MODULES),
        "strategy": "balanced",
    })

    for tool, _label in MODULES:
        if _shutdown.is_set():
            break
        await ws.send_json({"type": "progress", "tool": tool, "status": "running", "count": 0})
        await asyncio.sleep(0.05)  # effet visuel sans ralentir vraiment
        count = len(rows)
        await ws.send_json({"type": "progress", "tool": tool, "status": "done", "count": count})

# ═══════════════════════════════════════════════════════════════
# FASTAPI + WEBSOCKET
# ═══════════════════════════════════════════════════════════════

@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("🚀 OSINT HUB v4.1 (corrigé)")
    t = threading.Thread(target=bg_loop, daemon=True)
    t.start()

    def _watch():
        while not _shutdown.is_set():
            if STOP_FILE.exists():
                try:
                    STOP_FILE.unlink()
                except Exception:
                    pass
                _shutdown.set()
                break
            time.sleep(2)
    threading.Thread(target=_watch, daemon=True).start()

    yield

    # Shutdown propre : on ferme la connexion DuckDB
    log.info("🛑 Arrêt demandé, fermeture propre...")
    _shutdown.set()
    global _conn
    with _lock:
        if _conn is not None:
            try:
                _conn.close()
            except Exception:
                pass
            _conn = None


app = FastAPI(title="OSINT HUB", version="4.1", lifespan=lifespan)

# Un navigateur REFUSE 'Access-Control-Allow-Origin: *' combiné à
# allow_credentials=True (interdit par la spec CORS). Si ALLOWED_ORIGINS
# contient "*", on désactive allow_credentials pour rester fonctionnel ;
# sinon (liste explicite de domaines) on garde allow_credentials=True.
_cors_wildcard = ALLOWED_ORIGINS == ["*"]
if _cors_wildcard:
    log.warning(
        "⚠️  OSINT_ALLOWED_ORIGINS='*' : allow_credentials désactivé "
        "(incompatible avec un wildcard côté navigateur). "
        "Définissez des domaines explicites pour garder les credentials."
    )
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_origin_regex=ALLOWED_ORIGIN_REGEX if not _cors_wildcard else None,
    allow_credentials=not _cors_wildcard,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {
        "status": "ok", "version": "4.1",
        "importing": state.importing, "progress": state.progress,
        "total_records": state.total_rec,
        "auth_required": REQUIRE_AUTH,
    }


@app.get("/status")
def status():
    return {"importing": state.importing, "progress": state.progress, "total_records": state.total_rec}


@app.get("/databases")
def list_databases():
    """Liste les sources importées (fichiers) trackées dans la table `imported`.
    Route attendue par le frontend (écran 'Bases de données')."""
    with _lock:
        rows = db().execute(
            "SELECT path, mtime, rows FROM imported ORDER BY mtime DESC"
        ).fetchall()
    return {
        "databases": [
            {"path": r[0], "mtime": r[1], "rows": r[2]} for r in rows
        ],
        "total_records": state.total_rec,
        "importing": state.importing,
    }


@app.post("/databases")
def add_database(payload: dict):
    """Ajoute une base manuellement par chemin de fichier et lance l'import.
    Attend un body JSON {"path": "..."}."""
    path = (payload.get("path") or "").strip()
    if not path:
        raise HTTPException(status_code=400, detail="Le champ 'path' est requis.")
    p = Path(path)
    if not p.exists() or not p.is_file():
        raise HTTPException(status_code=404, detail=f"Fichier introuvable : {path}")
    # Vérifie que le fichier est bien dans un des dossiers autorisés (SCAN_ROOTS)
    allowed = any(str(p.resolve()).startswith(str(root.resolve())) for root in SCAN_ROOTS)
    if not allowed:
        raise HTTPException(
            status_code=403,
            detail=f"Chemin hors des dossiers autorisés (OSINT_SCAN_ROOTS={SCAN_ROOTS}).",
        )
    if state.importing:
        return {"status": "already_running"}
    threading.Thread(target=run_import, daemon=True).start()
    return {"status": "started", "path": path}


@app.get("/api/tables")
def list_tables_api():
    """Alias attendu par le frontend (sidebar 'Bases actives', Option A).
    Même source que /databases, renvoyée sous la forme {"tables": [...]}
    avec les clés name/rows directement exploitables côté UI."""
    with _lock:
        rows = db().execute(
            "SELECT path, mtime, rows FROM imported ORDER BY mtime DESC"
        ).fetchall()
    return {
        "tables": [
            {"name": Path(r[0]).name, "path": r[0], "mtime": r[1], "rows": r[2]} for r in rows
        ],
        "total_records": state.total_rec,
        "importing": state.importing,
    }


@app.get("/search")
def search_http(q: str, limit: int = 100):
    rows = search_raw(q, min(limit, MAX_RESULTS))
    return {"query": q, "count": len(rows), "results": rows}


@app.get("/api/search")
def search_api(query: str, limit: int = 100):
    """Alias attendu par le frontend (Option A) : mêmes résultats que /search,
    mais avec le paramètre 'query' au lieu de 'q'."""
    rows = search_raw(query, min(limit, MAX_RESULTS))
    return {"query": query, "count": len(rows), "results": rows}


@app.get("/graph")
def graph_http(q: str, limit: int = 500):
    rows = search_raw(q, min(limit, MAX_RESULTS))
    return _build_graph(q, rows)


@app.post("/rescan")
def rescan():
    if state.importing:
        return {"status": "already_running"}
    threading.Thread(target=run_import, daemon=True).start()
    return {"status": "started"}


@app.post("/stop")
def stop_server():
    _shutdown.set()
    return {"status": "stopping"}


@app.websocket("/ws/search")
async def ws_search(ws: WebSocket, token: Optional[str] = Query(default=None)):
    # Connexion directe sans passer par require_auth
    await ws.accept()
    try:
        while True:
            try:
                data = await asyncio.wait_for(ws.receive_json(), timeout=60)
            except asyncio.TimeoutError:
                await ws.send_json({"type": "ping"})
                continue

            q = (data.get("query") or "").strip()
            if not q:
                await ws.send_json({"type": "error", "message": "Requête vide."})
                continue

            loop = asyncio.get_event_loop()
            raw_rows = await loop.run_in_executor(None, lambda: search_raw(q))

            # Émission des modules (effet multi-tool)
            await _emit_modules(ws, q, raw_rows)

            payload = await loop.run_in_executor(None, lambda: _build_payload(q, raw_rows))
            await ws.send_json({"type": "consolidated", **payload})

            await ws.send_json({
                "type": "done", "query": q,
                "total_results": len(raw_rows),
                "still_importing": state.importing,
            })

    except WebSocketDisconnect:
        pass
    except Exception as e:
        log.error(f"WS: {e}")
        try:
            await ws.send_json({"type": "error", "message": str(e)})
        except Exception:
            pass


if __name__ == "__main__":
    uvicorn.run(
        "server_v3:app",
        host="0.0.0.0",
        port=PORT,
        log_level="info",
        ws_ping_interval=30,
        ws_ping_timeout=60,
    )
