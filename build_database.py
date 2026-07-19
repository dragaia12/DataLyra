#!/usr/bin/env python3
"""
build_database.py — OSINT HUB
==============================
Ingère les fichiers sources OSINT (JSON / JSONL / CSV / TXT) dans DuckDB,
optimise physiquement le fichier (tri + zone-maps + index ART + FTS),
puis produit un `database.db` unique prêt à être servi statiquement et
interrogé depuis le navigateur via duckdb-wasm (duckdb-client.ts).

Schéma cible :
    id           BIGINT PRIMARY KEY   — hash SHA-1 stable (reproducible)
    src          VARCHAR              — nom du fichier source
    email        VARCHAR
    username     VARCHAR
    password_set BOOLEAN              — TRUE si un mot de passe était présent (jamais le clair)
    hash_val     VARCHAR              — MD5 / SHA1 / SHA256 trouvé
    domain       VARCHAR              — domaine extrait de l'email ou colonne dédiée
    ip           VARCHAR
    phone        VARCHAR
    raw          VARCHAR              — extrait non-sensible (emails + IPs, jamais password)

Usage :
    pip install duckdb==1.5.4 --break-system-packages
    python3 build_database.py --input "./osint_data/*.json" --output database.db
    python3 build_database.py --input "./osint_data/*.csv" --output database.db --fts-lang french

Compatibilité duckdb-wasm :
    Générez database.db avec la MÊME version majeure.mineure du paquet Python `duckdb`
    que celle embarquée dans @duckdb/duckdb-wasm côté frontend.
    Au moment de la rédaction : DuckDB 1.5.x des deux côtés.
    Vérifiez sur https://github.com/duckdb/duckdb-wasm avant de figer la version.
"""

import argparse
import csv
import glob
import hashlib
import os
import re
import sys
import time
from pathlib import Path

import duckdb

# ── REGEX ─────────────────────────────────────────────────────────────────────
RE_EMAIL = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
RE_IP    = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
RE_PHONE = re.compile(r"(?:\+|00)(?:\d[\s\-]?){6,14}\d")
RE_HASH  = re.compile(r"\b[0-9a-fA-F]{32,64}\b")

# ── MAPPING COLONNES → champs OSINT ──────────────────────────────────────────
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
    "phone":    ["phone", "telephone", "tel", "mobile", "cell", "numero",
                 "phone_number", "phonenumber", "msisdn"],
    "hash_val": ["hash", "md5", "sha1", "sha256", "sha512", "hashed",
                 "password_hash", "hash_value"],
}

BATCH_SIZE = 200_000


def _normalize_col(s: str) -> str:
    return s.lower().strip().replace(" ", "_").replace("-", "_")


def _match_col(name: str) -> str | None:
    n = _normalize_col(name)
    for field, patterns in COL_MAP.items():
        for pat in patterns:
            if pat == n or pat in n or n in pat:
                return field
    return None


def _stable_id(key: str) -> int:
    """ID déterministe basé sur SHA-1 — stable entre relances (pas de hash() Python)."""
    h = hashlib.sha1(key.encode("utf-8", errors="replace")).digest()
    return int.from_bytes(h[:8], "big", signed=True)


def _safe_raw(parts: list[str]) -> str:
    """
    Construit le champ `raw` sans jamais inclure de mot de passe.
    Ne conserve que les tokens reconnus (email, IP, hash, phone).
    """
    tokens: list[str] = []
    joined = " ".join(parts)
    for rx in (RE_EMAIL, RE_IP, RE_HASH, RE_PHONE):
        for m in rx.findall(joined):
            tokens.append(m if isinstance(m, str) else m[0])
    return " | ".join(dict.fromkeys(tokens))[:1000]


def _enrich_from_text(text: str) -> dict:
    """Extrait email/IP/phone/hash d'une chaîne brute quand le mapping échoue."""
    r: dict = {}
    m = RE_EMAIL.search(text)
    if m:
        r["email"] = m.group(0)
        r["domain"] = m.group(0).split("@", 1)[1]
    m = RE_IP.search(text)
    if m:
        r["ip"] = m.group(0)
    m = RE_PHONE.search(text)
    if m:
        r["phone"] = m.group(0).strip()
    m = RE_HASH.search(text)
    if m:
        r["hash_val"] = m.group(0)
    return r


def _row_from_dict(obj: dict, src: str, idx: int) -> dict:
    """Mappe un objet JSON/CSV quelconque vers le schéma OSINT cible."""
    r: dict = {}
    raw_parts: list[str] = []

    for k, v in obj.items():
        if v is None:
            continue
        val = str(v).strip()
        if not val:
            continue
        raw_parts.append(val)
        field = _match_col(k)
        if field and field not in r:
            r[field] = val

    # Si aucun champ reconnu → enrichissement regex
    if not any(r.get(f) for f in ("email", "username", "ip", "domain")):
        r.update(_enrich_from_text(" ".join(raw_parts)))

    # Domaine depuis email
    email = r.get("email", "")
    if not r.get("domain") and email and "@" in email:
        r["domain"] = email.split("@", 1)[1]

    r["raw"] = _safe_raw(raw_parts)
    return r


def _make_row_tuple(r: dict, src: str, idx: int) -> tuple:
    """Produit un tuple prêt pour executemany() vers la table `records`."""
    email    = (r.get("email")    or "").strip()[:500] or None
    username = (r.get("username") or "").strip()[:500] or None
    password = (r.get("password") or "").strip()
    domain   = (r.get("domain")   or "").strip()[:255] or None
    ip       = (r.get("ip")       or "").strip()[:45]  or None
    phone    = (r.get("phone")    or "").strip()[:50]  or None
    hash_val = (r.get("hash_val") or "").strip()[:128] or None
    raw      = (r.get("raw")      or "")[:1000] or None

    if not domain and email and "@" in email:
        domain = email.split("@", 1)[1]

    key = f"{src}|{email}|{username}|{hash_val}|{domain}|{ip}|{idx}"
    uid = _stable_id(key)

    return (uid, src, email, username, bool(password), hash_val, domain, ip, phone, raw)


# ── INIT TABLE ────────────────────────────────────────────────────────────────

def _create_table(con: duckdb.DuckDBPyConnection) -> None:
    con.execute("""
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


# ── IMPORT JSON (natif DuckDB — rapide) ───────────────────────────────────────

def _import_json_native(con: duckdb.DuckDBPyConnection, path: Path, src: str) -> int | None:
    """
    Utilise read_json_auto() (parseur C++) pour les fichiers JSON/JSONL.
    Détecte les colonnes, les mappe vers le schéma, insère en une passe.
    Retourne None si DuckDB ne peut pas lire le fichier (fallback Python).
    """
    safe = str(path).replace("\\", "/").replace("'", "''")
    try:
        schema = con.execute(
            f"SELECT column_name FROM "
            f"(DESCRIBE SELECT * FROM read_json_auto('{safe}', maximum_object_size=104857600) LIMIT 0)"
        ).fetchall()
    except Exception as e:
        print(f"    [json_native] schema échec ({e}) → fallback Python")
        return None

    cols = [r[0] for r in schema]
    if not cols:
        return None

    mappings: dict[str, str] = {}
    for col in cols:
        field = _match_col(col)
        if field:
            mappings[col] = field

    if not mappings:
        print(f"    [json_native] aucune colonne reconnue → fallback Python")
        return None

    # Construction du SELECT mappé
    used: set[str] = set()
    parts: list[str] = []
    for col, field in mappings.items():
        safe_col = f'"{col}"'
        if field not in used:
            parts.append(f"TRY_CAST({safe_col} AS VARCHAR) AS {field}")
            used.add(field)

    sel = ", ".join(parts)

    email_expr    = "email"       if "email"    in used else "NULL"
    username_expr = "username"    if "username" in used else "NULL"
    pwd_expr      = "password IS NOT NULL AND password <> ''" if "password" in used else "FALSE"
    hash_expr     = "hash_val"    if "hash_val" in used else "NULL"
    domain_expr   = (
        "COALESCE(domain, CASE WHEN email LIKE '%@%' THEN split_part(email,'@',2) ELSE NULL END)"
        if "domain" in used or "email" in used
        else "NULL"
    )
    ip_expr    = "ip"    if "ip"    in used else "NULL"
    phone_expr = "phone" if "phone" in used else "NULL"

    try:
        con.execute(f"""
            INSERT INTO records
            SELECT
                hash(CONCAT_WS('|', '{src}', {email_expr}, {username_expr},
                               {hash_expr}, {domain_expr}, {ip_expr}))::BIGINT AS id,
                '{src}' AS src,
                {email_expr},
                {username_expr},
                {pwd_expr},
                {hash_expr},
                {domain_expr},
                {ip_expr},
                {phone_expr},
                NULL AS raw
            FROM (SELECT {sel} FROM read_json_auto('{safe}', maximum_object_size=104857600,
                          union_by_name=true)) t
            ON CONFLICT (id) DO NOTHING
        """)
        n = con.execute(f"SELECT COUNT(*) FROM records WHERE src='{src}'").fetchone()[0]
        return n
    except Exception as e:
        print(f"    [json_native] insert échec ({e}) → fallback Python")
        return None


# ── IMPORT CSV (natif DuckDB) ─────────────────────────────────────────────────

def _import_csv_native(con: duckdb.DuckDBPyConnection, path: Path, src: str) -> int | None:
    safe = str(path).replace("\\", "/").replace("'", "''")
    try:
        schema = con.execute(
            f"SELECT column_name FROM "
            f"(DESCRIBE SELECT * FROM read_csv_auto('{safe}', ignore_errors=true) LIMIT 0)"
        ).fetchall()
    except Exception as e:
        print(f"    [csv_native] schema échec ({e}) → fallback Python")
        return None

    cols = [r[0] for r in schema]
    mappings: dict[str, str] = {}
    for col in cols:
        field = _match_col(col)
        if field:
            mappings[col] = field

    if not mappings:
        return None

    used: set[str] = set()
    parts: list[str] = []
    for col, field in mappings.items():
        safe_col = f'"{col}"'
        if field not in used:
            parts.append(f"TRY_CAST({safe_col} AS VARCHAR) AS {field}")
            used.add(field)

    sel = ", ".join(parts)
    email_expr    = "email"    if "email"    in used else "NULL"
    username_expr = "username" if "username" in used else "NULL"
    pwd_expr      = "password IS NOT NULL AND password <> ''" if "password" in used else "FALSE"
    hash_expr     = "hash_val" if "hash_val" in used else "NULL"
    domain_expr   = (
        "COALESCE(domain, CASE WHEN email LIKE '%@%' THEN split_part(email,'@',2) ELSE NULL END)"
        if "domain" in used or "email" in used
        else "NULL"
    )
    ip_expr    = "ip"    if "ip"    in used else "NULL"
    phone_expr = "phone" if "phone" in used else "NULL"

    try:
        con.execute(f"""
            INSERT INTO records
            SELECT
                hash(CONCAT_WS('|', '{src}', {email_expr}, {username_expr},
                               {hash_expr}, {domain_expr}, {ip_expr}))::BIGINT AS id,
                '{src}' AS src,
                {email_expr},
                {username_expr},
                {pwd_expr},
                {hash_expr},
                {domain_expr},
                {ip_expr},
                {phone_expr},
                NULL AS raw
            FROM (SELECT {sel} FROM read_csv_auto('{safe}', ignore_errors=true)) t
            ON CONFLICT (id) DO NOTHING
        """)
        n = con.execute(f"SELECT COUNT(*) FROM records WHERE src='{src}'").fetchone()[0]
        return n
    except Exception as e:
        print(f"    [csv_native] insert échec ({e}) → fallback Python")
        return None


# ── FALLBACK Python ligne par ligne ───────────────────────────────────────────

def _insert_batch(con: duckdb.DuckDBPyConnection, batch: list[tuple]) -> None:
    if not batch:
        return
    con.executemany(
        "INSERT INTO records VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT (id) DO NOTHING",
        batch
    )


def _import_python_fallback(con: duckdb.DuckDBPyConnection, path: Path, src: str) -> int:
    """Fallback universel : lit ligne par ligne avec regex."""
    ext = path.suffix.lower()
    batch: list[tuple] = []
    total = 0

    def flush():
        nonlocal total
        _insert_batch(con, batch)
        total += len(batch)
        con.commit()
        batch.clear()

    if ext in (".json",):
        import json
        with path.open("r", encoding="utf-8", errors="replace") as f:
            try:
                data = json.load(f)
            except Exception:
                f.seek(0)
                data = [json.loads(line) for line in f if line.strip()]
        if isinstance(data, dict):
            data = [data]
        for i, obj in enumerate(data):
            if not isinstance(obj, dict):
                continue
            r = _row_from_dict(obj, src, i)
            batch.append(_make_row_tuple(r, src, i))
            if len(batch) >= BATCH_SIZE:
                flush()
        flush()

    elif ext in (".jsonl", ".ndjson"):
        i = 0
        import json
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                r = _row_from_dict(obj, src, i)
                batch.append(_make_row_tuple(r, src, i))
                i += 1
                if len(batch) >= BATCH_SIZE:
                    flush()
        flush()

    elif ext in (".csv", ".tsv"):
        with path.open("r", encoding="utf-8", errors="replace") as f:
            sample = "".join(f.readline() for _ in range(5))
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=":,;|\t")
            sep = dialect.delimiter
        except Exception:
            sep = ","
        with path.open("r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f, delimiter=sep)
            for i, row in enumerate(reader):
                r = _row_from_dict(dict(row), src, i)
                batch.append(_make_row_tuple(r, src, i))
                if len(batch) >= BATCH_SIZE:
                    flush()
        flush()

    else:
        # .txt et autres : enrichissement regex ligne par ligne
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                r = _enrich_from_text(line)
                r["raw"] = _safe_raw([line])
                batch.append(_make_row_tuple(r, src, i))
                if len(batch) >= BATCH_SIZE:
                    flush()
        flush()

    return total


# ── DISPATCHER PAR FICHIER ────────────────────────────────────────────────────

def import_file(con: duckdb.DuckDBPyConnection, path: Path) -> int:
    src = path.name
    ext = path.suffix.lower()
    size_mb = path.stat().st_size / 1024 / 1024
    print(f"  📂 {src}  ({size_mb:.1f} MB)")
    t0 = time.time()

    total = 0
    if ext in (".json", ".jsonl", ".ndjson"):
        result = _import_json_native(con, path, src)
        total = result if result is not None else _import_python_fallback(con, path, src)
    elif ext in (".csv", ".tsv"):
        result = _import_csv_native(con, path, src)
        total = result if result is not None else _import_python_fallback(con, path, src)
    else:
        total = _import_python_fallback(con, path, src)

    elapsed = time.time() - t0
    rate = total / elapsed if elapsed > 0 else 0
    print(f"     ✓ {total:,} records en {elapsed:.1f}s ({rate:,.0f} rec/s)")
    return total


# ── BUILD PRINCIPAL ───────────────────────────────────────────────────────────

def build(input_glob: str, output_path: str, fts_lang: str = "none") -> None:
    files = sorted(glob.glob(input_glob, recursive=True))
    if not files:
        sys.exit(f"[ERREUR] Aucun fichier ne correspond à : {input_glob}")

    print(f"\n{'='*60}")
    print(f"  OSINT HUB — build_database.py")
    print(f"{'='*60}")
    print(f"  {len(files)} fichier(s) source détecté(s)")
    print(f"  Sortie : {output_path}\n")

    # Repart toujours d'un fichier neuf pour éviter les collisions d'index
    if os.path.exists(output_path):
        os.remove(output_path)
        print(f"  Ancien {output_path} supprimé.\n")

    t0 = time.time()
    con = duckdb.connect(output_path)
    con.execute(f"PRAGMA threads={os.cpu_count() or 4}")
    con.execute("SET preserve_insertion_order=false")

    # ── 1) INGESTION dans une table temporaire _raw ────────────────────────────
    print("[1/4] Ingestion des fichiers sources...")
    _create_table(con)

    grand_total = 0
    for i, fp in enumerate(files, 1):
        path = Path(fp)
        print(f"\n  [{i}/{len(files)}]")
        try:
            n = import_file(con, path)
            grand_total += n
        except Exception as e:
            print(f"     ❌ Erreur : {e}")
    con.commit()

    print(f"\n  → {grand_total:,} records ingérés au total")

    # ── 2) CLUSTERING PHYSIQUE ─────────────────────────────────────────────────
    # Trier physiquement sur (domain, email) permet à DuckDB d'éliminer des
    # row-groups entiers via les zone-maps avant de scanner les autres colonnes.
    # Résultat : les filtres "domain = ?" et "email = ?" sont très rapides
    # même sans index — et encore plus rapides avec.
    print("\n[2/4] Tri physique pour le row-group pruning...")
    con.execute("""
        CREATE TABLE records_sorted AS
        SELECT * FROM records
        ORDER BY domain NULLS LAST, email NULLS LAST, username NULLS LAST
    """)
    con.execute("DROP TABLE records")
    con.execute("ALTER TABLE records_sorted RENAME TO records")
    con.commit()
    print("  ✓ Données triées (domain, email, username)")

    # ── 3) INDEX ART ───────────────────────────────────────────────────────────
    # Les index ART accélèrent les égalités exactes (=) et les préfixes (LIKE 'x%').
    # Ils n'accélèrent PAS ILIKE '%terme%' — pour ça, voir le FTS ci-dessous.
    # On indexe les colonnes les plus filtrées dans l'UI de recherche OSINT.
    print("\n[3/4] Création des index ART...")
    index_cols = {
        "email":    "idx_email",
        "username": "idx_username",
        "domain":   "idx_domain",
        "ip":       "idx_ip",
        "phone":    "idx_phone",
        "hash_val": "idx_hash_val",
    }
    for col, idx_name in index_cols.items():
        try:
            con.execute(f"CREATE INDEX {idx_name} ON records({col})")
            print(f"  ✓ idx {col}")
        except Exception as e:
            print(f"  ⚠ idx {col} : {e}")

    # ── 4) INDEX FULL-TEXT (optionnel, sur `raw`) ──────────────────────────────
    # Permet des recherches de sous-chaîne en O(résultats) avec scoring BM25.
    # Utile pour les requêtes génériques ("contient ce mot n'importe où").
    # Si le téléchargement de l'extension échoue (sandbox sans Internet),
    # la recherche ILIKE reste fonctionnelle.
    print("\n[4/4] Index Full-Text sur `raw` (optionnel)...")
    fts_ok = False
    try:
        con.execute("INSTALL fts")
        con.execute("LOAD fts")
        con.execute(f"""
            PRAGMA create_fts_index(
                'records', 'id', 'raw',
                stemmer='{fts_lang}',
                ignore='(\\.|[^a-z])+',
                lower=1,
                overwrite=1
            )
        """)
        fts_ok = True
        print("  ✓ Index FTS créé sur `raw`")
    except Exception as e:
        print(f"  ⚠ FTS non disponible ({e})")
        print("    → La recherche ILIKE restera fonctionnelle.")

    # ── FINALISATION ───────────────────────────────────────────────────────────
    con.execute("CHECKPOINT")
    file_size_mb = os.path.getsize(output_path) / (1024 * 1024)
    elapsed = time.time() - t0
    con.close()

    print(f"\n{'='*60}")
    print(f"  ✅ BUILD TERMINÉ en {elapsed:.1f}s")
    print(f"  Records indexés  : {grand_total:,}")
    print(f"  Index FTS        : {'OUI' if fts_ok else 'NON (ILIKE actif)'}")
    print(f"  Fichier          : {output_path}  ({file_size_mb:.2f} Mo)")
    print(f"{'='*60}")
    print()
    print("ÉTAPES SUIVANTES :")
    print("  1. Déposez database.db sur votre CDN/hébergement statique.")
    print("     (S3, Cloudflare R2/Pages, Netlify, GitHub Pages...)")
    print("  2. Vérifiez que le serveur répond aux Range Requests HTTP")
    print("     (Accept-Ranges: bytes) — requis par duckdb-wasm.")
    print("  3. Désactivez la compression HTTP (gzip/br) sur ce fichier.")
    print("     DuckDB utilise déjà sa propre compression colonnaire.")
    print("  4. Mettez à jour DB_URL dans duckdb-client.ts.")
    print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Génère database.db OSINT depuis des fichiers JSON/CSV/TXT",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--input", default="./osint_data/**/*",
        help="Glob vers les fichiers sources (défaut: ./osint_data/**/*)"
    )
    parser.add_argument(
        "--output", default="database.db",
        help="Chemin du fichier .db à produire (défaut: database.db)"
    )
    parser.add_argument(
        "--fts-lang", default="none",
        help="Stemmer pour l'index Full-Text : 'none', 'french', 'english' (défaut: none)"
    )
    args = parser.parse_args()
    build(args.input, args.output, args.fts_lang)
