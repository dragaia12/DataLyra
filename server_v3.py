"""
OSINT HUB v4.1 — Backend universel DuckDB (VERSION CORRIGEE + OPTIMISEE)
=============================================================
"""
import asyncio
import csv
import hashlib
import io
import json
import logging
import os
import re
import threading
import time
import warnings
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

import duckdb
from dotenv import load_dotenv
import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.websockets import WebSocketState

warnings.filterwarnings('ignore', category=SyntaxWarning)
load_dotenv()

# ── CONFIG ────────────────────────────────────────────────────
_DEFAULT_ROOT = str((Path(__file__).parent / "osint_data").resolve())
SCAN_ROOTS = [Path(p) for p in os.environ.get("OSINT_SCAN_ROOTS", _DEFAULT_ROOT).split(",") if p.strip()]
DB_PATH = os.environ.get("OSINT_DB_PATH", str(Path(__file__).parent / "osint_master.duckdb"))
STOP_FILE = Path(os.environ.get("OSINT_STOP_FILE", str(Path(__file__).parent / "STOP")))
PORT = int(os.environ.get("PORT", "8765"))
RESCAN_SECS = int(os.environ.get("OSINT_RESCAN_SECS", "300"))
MAX_RESULTS = int(os.environ.get("OSINT_MAX_RESULTS", "1000"))
LOG_FILE = os.environ.get("OSINT_LOG_FILE", str(Path(__file__).parent / "osint_service.log"))
TMP_DIR = os.environ.get("OSINT_TMP_DIR", str(Path(__file__).parent / "osint_tmp"))

# ── AUTHENTIFICATION ──────────────────────────────────────────
SUPABASE_JWT_SECRET = os.environ.get("OSINT_SUPABASE_JWT_SECRET", "COLLE_TON_VRAI_JWT_SECRET_ICI")
REQUIRE_AUTH = os.environ.get("OSINT_REQUIRE_AUTH", "1") == "1"
ALLOWED_ORIGINS = [o.strip() for o in os.environ.get("OSINT_ALLOWED_ORIGINS", "*").split(",") if o.strip()]
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

# ── REGEX GLOBAUX (Corrigés avec raw strings) ─────────────────
RE_EMAIL = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
RE_IP = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
RE_DOMAIN = re.compile(r"@([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})")
RE_PHONE = re.compile(r"(?:\+|00)(?:\d[\s\-]?){6,14}\d")
RE_HASH = re.compile(r"\b[0-9a-fA-F]{32,64}\b")

SEPARATORS = [":", "|", ";", "\t", ",", " "]

_SQL_RE_EMAIL = "[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}"
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
    for col in ["email", "username", "domain", "ip", "phone", "hash_val"]:
        try:
            _conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{col} ON records({col})")
        except Exception:
            pass
    _migrate(_conn)
    _conn.commit()
    return _conn

def _migrate(c):
    try:
        try:
            has_pk = c.execute(
                "SELECT COUNT(*) FROM duckdb_constraints() "
                "WHERE table_name='records' AND constraint_type='PRIMARY KEY'"
            ).fetchone()[0]
            if not has_pk:
                log.info("Migration: recréation de records avec PRIMARY KEY...")
                for _idx in ["idx_email","idx_username","idx_domain","idx_ip","idx_phone","idx_hash_val"]:
                    try: c.execute(f"DROP INDEX IF EXISTS {_idx}")
                    except Exception: pass
                c.execute("ALTER TABLE records RENAME TO records_old")
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
                old_cols = {r[0].lower() for r in c.execute("DESCRIBE records_old").fetchall()}
                pwd_expr = "COALESCE(password_set, FALSE)" if "password_set" in old_cols else "FALSE"
                hash_expr = "hash_val" if "hash_val" in old_cols else "NULL"
                phone_expr = "phone" if "phone" in old_cols else "NULL"
                raw_expr = "raw" if "raw" in old_cols else "NULL"
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
        if "password" in existing and "password_set" not in existing:
            c.execute("ALTER TABLE records ADD COLUMN password_set BOOLEAN DEFAULT FALSE")
            c.execute("UPDATE records SET password_set = TRUE WHERE password IS NOT NULL AND password <> ''")
            log.info("Migration: colonne password_set ajoutée (depuis password).")
        if "password_set" not in existing and "password" not in existing:
            c.execute("ALTER TABLE records ADD COLUMN password_set BOOLEAN DEFAULT FALSE")
        c.commit()
    except Exception as e:
        log.debug(f"Migration: {e}")

class State:
    importing = False
    progress = {"done": 0, "total": 0, "cur": "", "phase": "idle"}
    total_rec = 0
state = State()

def _stable_id(key: str) -> int:
    h = hashlib.sha1(key.encode("utf-8")).digest()
    return int.from_bytes(h[:8], "big") % 9223372036854775807

_cached_mtimes: dict[str, float] = {}

def already(path: str, mtime: float) -> bool:
    if path in _cached_mtimes and abs(_cached_mtimes[path] - mtime) < 1:
        return True
    try:
        with _lock:
            r = db().execute("SELECT mtime FROM imported WHERE path=?", [path]).fetchone()
        is_cached = bool(r and abs(r[0] - mtime) < 1)
        if is_cached:
            _cached_mtimes[path] = mtime
        return is_cached
    except Exception:
        return False

def mark(path: str, mtime: float, rows: int):
    with _lock:
        db().execute(
            "INSERT INTO imported VALUES(?,?,?) ON CONFLICT (path) DO UPDATE SET mtime=excluded.mtime, rows=excluded.rows",
            [path, mtime, rows]
        )
        db().commit()
        _cached_mtimes[path] = mtime

def mask_password(pwd: str) -> str:
    if not pwd:
        return ""
    if len(pwd) <= 3:
        return "*" * len(pwd)
    return pwd[:2] + "*" * (len(pwd) - 3) + pwd[-1]

# ── PARSERS ET HELPERS ────────────────────────────────────────
def _detect_type(query: str) -> str:
    q = query.strip()
    if RE_EMAIL.fullmatch(q):
        return "email"
    if RE_IP.fullmatch(q):
        return "ip"
    if RE_PHONE.fullmatch(q):
        return "phone"
    if RE_HASH.fullmatch(q):
        return "hash"
    if "." in q and " " not in q:
        return "domain"
    return "general"

def _build_payload(query: str, rows: list[dict]) -> dict:
    return {
        "query": query,
        "total": len(rows),
        "results": rows,
        "stats": {
            "emails": sum(1 for r in rows if r.get("email")),
            "ips": sum(1 for r in rows if r.get("ip")),
            "phones": sum(1 for r in rows if r.get("phone")),
        }
    }

def _detect_separator(sample_lines: list[str]) -> str:
    scores = {}
    for sep in SEPARATORS:
        counts = [len(line.split(sep)) for line in sample_lines if line.strip()]
        if counts:
            avg = sum(counts) / len(counts)
            variance = sum((c - avg) ** 2 for c in counts) / len(counts)
            if avg > 1.5 and variance < 5:
                scores[sep] = avg / (1 + variance)
    return max(scores, key=scores.get) if scores else ":"

def _sanitized_raw(raw: str) -> str:
    if not raw:
        return ""
    tokens = []
    for rx in (RE_EMAIL, RE_IP, RE_HASH, RE_PHONE):
        for m in rx.findall(raw):
            tokens.append(m if isinstance(m, str) else m[0])
    return " | ".join(dict.fromkeys(tokens))[:1000]

EXTS = {".csv", ".tsv", ".json", ".jsonl", ".ndjson", ".txt", ".sql"}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", "target"}

def _scan_root(root: Path) -> list[Path]:
    out: list[Path] = []
    stack: list[Path] = [root]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                for entry in it:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            if entry.name not in SKIP_DIRS:
                                stack.append(Path(entry.path))
                        elif entry.is_file(follow_symlinks=False):
                            ext = os.path.splitext(entry.name)[1].lower()
                            if ext in EXTS:
                                out.append(Path(entry.path))
                    except OSError:
                        continue
        except OSError:
            continue
    return out

def collect() -> list[Path]:
    roots = [r for r in SCAN_ROOTS if r.exists()]
    if not roots:
        return []
    found: list[Path] = []
    seen: set[str] = set()
    workers = min(8, max(1, len(roots)))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for result in ex.map(_scan_root, roots):
            for f in result:
                key = str(f).lower()
                if key not in seen:
                    seen.add(key)
                    found.append(f)
    return found

def _duckdb_native_import(p: Path, src: str, ext: str) -> int:
    safe = str(p).replace("'", "''")
    safe_src = src.replace("'", "''")
    try:
        with _lock:
            c = db()
            before = c.execute("SELECT COUNT(*) FROM records").fetchone()[0]
            if ext in (".csv", ".tsv"):
                c.execute(f"""
                    INSERT INTO records
                    SELECT
                        abs(hash('{safe_src}' || CAST(row_number() OVER() AS VARCHAR))) % 9223372036854775807,
                        '{safe_src}',
                        regexp_extract(line, '{_SQL_RE_EMAIL}', 0),
                        NULL, FALSE, NULL,
                        regexp_extract(line, '{_SQL_RE_DOMAIN}', 1),
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
                        regexp_extract(line, '{_SQL_RE_EMAIL}', 0),
                        NULL, FALSE, NULL,
                        regexp_extract(line, '{_SQL_RE_DOMAIN}', 1),
                        NULL, NULL,
                        line
                    FROM read_csv('{safe}', columns={{'line':'VARCHAR'}},
                        header=false, ignore_errors=true, parallel=true)
                    WHERE trim(line) != ''
                    ON CONFLICT (id) DO NOTHING
                """)
                c.commit()
            elif ext in (".json", ".jsonl", ".ndjson"):
                c.execute(f"""
                    INSERT INTO records
                    SELECT
                        abs(hash('{safe_src}' || CAST(row_number() OVER() AS VARCHAR))) % 9223372036854775807,
                        '{safe_src}',
                        COALESCE(CAST(json_extract(json, '$.email') AS VARCHAR), CAST(json_extract(json, '$.mail') AS VARCHAR)),
                        COALESCE(CAST(json_extract(json, '$.username') AS VARCHAR), CAST(json_extract(json, '$.user') AS VARCHAR)),
                        json_extract(json, '$.password') IS NOT NULL,
                        COALESCE(CAST(json_extract(json, '$.hash') AS VARCHAR), CAST(json_extract(json, '$.md5') AS VARCHAR)),
                        CAST(json_extract(json, '$.domain') AS VARCHAR),
                        COALESCE(CAST(json_extract(json, '$.ip') AS VARCHAR), CAST(json_extract(json, '$.ip_address') AS VARCHAR)),
                        COALESCE(CAST(json_extract(json, '$.phone') AS VARCHAR), CAST(json_extract(json, '$.telephone') AS VARCHAR)),
                        CAST(json AS VARCHAR)
                    FROM read_json_auto('{safe}', format='auto', ignore_errors=true)
                    ON CONFLICT (id) DO NOTHING
                """)
                c.commit()
            else:
                return -1
            after = c.execute("SELECT COUNT(*) FROM records").fetchone()[0]
            return max(0, after - before)
    except Exception as e:
        log.debug(f"DuckDB natif {src}: {e} — fallback")
        return -1

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
    t0 = time.time()

    if ext in (".csv", ".tsv", ".txt", ".json", ".jsonl", ".ndjson"):
        try:
            with _lock:
                total = _duckdb_native_import(p, src, ext)
            if total >= 0:
                with _lock:
                    mark(str(p), mtime, total)
                return total
        except Exception:
            pass

    return 0

def run_import():
    if state.importing:
        return
    state.importing = True
    state.progress = {"done": 0, "total": 0, "cur": "", "phase": "scan"}
    try:
        files = collect()
        to_do = [f for f in files if not already(str(f), f.stat().st_mtime)]
        state.progress["total"] = len(to_do)
        state.progress["phase"] = "import"

        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(max_workers=2) as ex:
            futures = {ex.submit(import_file, f): f for f in to_do}
            for fut in as_completed(futures):
                if _shutdown.is_set():
                    break
                try:
                    fut.result()
                except Exception:
                    pass
                state.progress["done"] += 1
        with _lock:
            r = db().execute("SELECT COUNT(*) FROM records").fetchone()
            state.total_rec = r[0] if r else 0
        state.progress["phase"] = "idle"
    finally:
        state.importing = False

def bg_loop():
    for root in SCAN_ROOTS:
        try:
            root.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
    run_import()
    while not _shutdown.is_set():
        if _shutdown.wait(RESCAN_SECS):
            break
        run_import()

# ── RECHERCHE ─────────────────────────────────────────────────
def search_raw(query: str, limit: int = MAX_RESULTS) -> list[dict]:
    sql = "SELECT CAST(line AS VARCHAR) FROM records LIMIT 50000"
    try:
        with _lock:
            rows = db().execute(sql).fetchall()
        results = []
        q = query.lower().strip()
        for r in rows:
            line_content = r[0] or ""
            if q in line_content.lower():
                clean_line = line_content.replace('"', '').replace(',', '').strip()
                parts = clean_line.split(':')
                extracted_email = parts[0].strip() if len(parts) > 0 else line_content
                extracted_password = parts[1].strip() if len(parts) > 1 else ""
                results.append({
                    "source": "local_import",
                    "email": extracted_email,
                    "username": extracted_email,
                    "password": extracted_password,
                    "password_set": bool(extracted_password),
                    "hash_val": "",
                    "domain": extracted_email.split('@')[1] if '@' in extracted_email else "",
                    "ip": "", "phone": "",
                    "firstname": "", "lastname": "", "siret": "",
                    "address": "",
                    "raw": line_content
                })
                if len(results) >= limit:
                    break
        return results
    except Exception:
        return []

MODULES = [
    ("duckdb_local", "Base de données locale"),
    ("identity_parser", "Identité civile"),
    ("company_intel", "Registre d'entreprise"),
    ("address_geo", "Localisation postale"),
    ("email_reputation", "Réputation email"),
    ("domain_lookup", "Domaines associés"),
    ("ip_intel", "Renseignement IP"),
    ("phone_lookup", "Téléphones"),
    ("hash_check", "Empreintes / hashs"),
]

async def _emit_modules(ws: WebSocket, q: str, rows: list[dict]):
    q_type = _detect_type(q)
    await ws.send_json({
        "type": "detected",
        "targets": [{"value": q, "detected_type": q_type}],
    })
    await ws.send_json({
        "type": "start", "total_jobs": len(MODULES),
        "strategy": "balanced",
    })
    counts = {
        "identity_parser": sum(1 for r in rows if r.get("firstname") or r.get("lastname")),
        "company_intel": sum(1 for r in rows if r.get("siret")),
        "address_geo": sum(1 for r in rows if r.get("address")),
        "email_reputation": sum(1 for r in rows if r.get("email")),
        "domain_lookup": sum(1 for r in rows if r.get("domain")),
        "ip_intel": sum(1 for r in rows if r.get("ip")),
        "phone_lookup": sum(1 for r in rows if r.get("phone")),
        "hash_check": sum(1 for r in rows if r.get("hash_val")),
        "duckdb_local": len(rows)
    }
    for tool, _label in MODULES:
        if _shutdown.is_set():
            break
        await ws.send_json({"type": "progress", "tool": tool, "status": "running", "count": 0})
        await asyncio.sleep(0.04)
        count = counts.get(tool, len(rows))
        await ws.send_json({"type": "progress", "tool": tool, "status": "done", "count": count})

# ── FASTAPI ───────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("🚀 OSINT HUB v4.1 (corrigé + optimisé)")
    t = threading.Thread(target=bg_loop, daemon=True)
    t.start()
    yield
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

_cors_wildcard = ALLOWED_ORIGINS == ["*"]
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

@app.get("/api/databases")
@app.get("/databases")
def list_databases():
    with _lock:
        rows = db().execute("SELECT path, mtime, rows FROM imported ORDER BY mtime DESC").fetchall()
    return {
        "databases": [{"path": r[0], "mtime": r[1], "rows": r[2]} for r in rows],
        "total_records": state.total_rec,
        "importing": state.importing,
    }

@app.post("/api/databases")
@app.post("/databases")
def add_database(payload: dict):
    path = (payload.get("path") or "").strip()
    if not path:
        raise HTTPException(status_code=400, detail="Le champ 'path' est requis.")
    p = Path(path)
    if not p.exists() or not p.is_file():
        raise HTTPException(status_code=404, detail=f"Fichier introuvable : {path}")
    if state.importing:
        return {"status": "already_running"}
    threading.Thread(target=run_import, daemon=True).start()
    return {"status": "started", "path": path}

@app.get("/api/tables")
def list_tables_api():
    with _lock:
        rows = db().execute("SELECT path, mtime, rows FROM imported ORDER BY mtime DESC").fetchall()
    return {
        "tables": [{"name": Path(r[0]).name, "path": r[0], "mtime": r[1], "rows": r[2]} for r in rows],
        "total_records": state.total_rec,
        "importing": state.importing,
    }

@app.get("/search")
def search_legacy(q: str = Query(None), query: str = Query(None), limit: int = 100):
    target_query = query or q or ""
    rows = search_raw(target_query, min(limit, MAX_RESULTS))
    return {"query": target_query, "count": len(rows), "results": rows, "data": rows, "matches": rows}

@app.get("/api/search")
def search_api(query: Optional[str] = None, q: Optional[str] = None, limit: int = 100):
    target_query = query or q or ""
    rows = search_raw(target_query, min(limit, MAX_RESULTS))
    return {"query": target_query, "count": len(rows), "results": rows, "data": rows, "matches": rows}

@app.get("/graph")
def graph_http(q: str, limit: int = 500):
    rows = search_raw(q, min(limit, MAX_RESULTS))
    return {"query": q, "nodes": [], "edges": []}

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