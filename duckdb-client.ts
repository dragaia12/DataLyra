/**
 * duckdb-client.ts — OSINT HUB
 * ==============================
 * Couche d'accès DuckDB-Wasm pour le moteur de recherche client-side OSINT.
 *
 * Schéma de la table `records` :
 *   id           BIGINT PRIMARY KEY
 *   src          VARCHAR   — fichier source
 *   email        VARCHAR
 *   username     VARCHAR
 *   password_set BOOLEAN   — TRUE si un mot de passe était présent (jamais le clair)
 *   hash_val     VARCHAR   — MD5 / SHA1 / SHA256
 *   domain       VARCHAR
 *   ip           VARCHAR
 *   phone        VARCHAR
 *   raw          VARCHAR   — extrait non-sensible (emails + IPs)
 *
 * Architecture :
 *  1. Le moteur WASM est instancié UNE SEULE FOIS (singleton) via jsDelivr.
 *  2. database.db est ATTACHé via HTTP Range Requests : DuckDB-Wasm ne
 *     télécharge QUE les pages disque nécessaires à chaque requête.
 *  3. Les prepared statements sont mis en cache pour éviter de re-planifier
 *     la même requête à chaque frappe clavier.
 *
 * Pré-requis hébergement :
 *  - Le serveur doit répondre aux Range Requests (Accept-Ranges: bytes).
 *  - CORS : Access-Control-Allow-Origin + exposer Content-Range, Content-Length.
 *  - PAS de compression HTTP (gzip/br) sur database.db — ça casse le Range.
 *  - Cache long recommandé : Cache-Control: public, max-age=31536000, immutable
 */

import * as duckdb from "@duckdb/duckdb-wasm";
import type {
  AsyncDuckDB,
  AsyncDuckDBConnection,
  AsyncPreparedStatement,
} from "@duckdb/duckdb-wasm";

// ─── URL de la base (à adapter selon votre hébergement) ───────────────────────
// En développement, copiez database.db dans public/ et mettez "/database.db".
// En production : "https://votre-cdn.example.com/database.db"
const DB_URL = (import.meta as Record<string, unknown> & { env: Record<string, string> })
  .env?.VITE_OSINT_DB_URL ?? "/database.db";

// ─── Types ────────────────────────────────────────────────────────────────────

/** Une ligne de la table `records`. */
export interface OsintRecord {
  id: bigint;
  src: string | null;
  email: string | null;
  username: string | null;
  password_set: boolean;
  hash_val: string | null;
  domain: string | null;
  ip: string | null;
  phone: string | null;
  raw: string | null;
}

/** Paramètres de recherche multi-champs. */
export interface OsintSearchParams {
  /**
   * Terme de recherche. Testé en égalité exacte sur email / ip / domain / hash_val / phone,
   * et en sous-chaîne (ILIKE) sur username et raw.
   * Laissez vide pour lister tout (filtres seuls).
   */
  term: string;
  /** Limite optionnelle sur une colonne exacte (ex: domain = "gmail.com"). */
  filterDomain?: string;
  /** Limite optionnelle sur ip. */
  filterIp?: string;
  /** N'afficher que les enregistrements avec un mot de passe exposé. */
  onlyWithPassword?: boolean;
  /** Résultats par page (défaut 20). */
  limit?: number;
  /** Décalage pour la pagination (défaut 0). */
  offset?: number;
}

export interface OsintSearchResponse {
  rows: OsintRecord[];
  /** Nombre total de résultats (toutes pages). */
  total: number;
  /** Durée d'exécution SQL en ms. */
  tookMs: number;
}

// ─── État interne (singleton) ─────────────────────────────────────────────────

let _db: AsyncDuckDB | null = null;
let _conn: AsyncDuckDBConnection | null = null;
let _initPromise: Promise<void> | null = null;

// Cache de prepared statements : clé = signature des filtres actifs
const _stmtCache = new Map<string, AsyncPreparedStatement>();

// ─── Instanciation du moteur WASM ─────────────────────────────────────────────

async function _instantiateEngine(): Promise<AsyncDuckDB> {
  const bundles = duckdb.getJsDelivrBundles();
  const bundle = await duckdb.selectBundle(bundles);

  const workerUrl = URL.createObjectURL(
    new Blob([`importScripts("${bundle.mainWorker!}");`], {
      type: "text/javascript",
    })
  );

  const worker = new Worker(workerUrl);
  const logger = new duckdb.ConsoleLogger(duckdb.LogLevel.WARNING);
  const instance = new duckdb.AsyncDuckDB(logger, worker);
  await instance.instantiate(bundle.mainModule, bundle.pthreadWorker);
  URL.revokeObjectURL(workerUrl);
  return instance;
}

// ─── Initialisation (publique) ────────────────────────────────────────────────

/**
 * Initialise DuckDB-Wasm et attache database.db depuis l'URL configurée.
 * Idempotent : sûr à appeler plusieurs fois (n'initialise qu'une fois).
 *
 * @example
 *   await initOsintDb();                        // utilise DB_URL par défaut
 *   await initOsintDb("https://cdn.example.com/database.db");
 */
export async function initOsintDb(url: string = DB_URL): Promise<void> {
  if (_initPromise) return _initPromise;

  _initPromise = (async () => {
    _db = await _instantiateEngine();
    _conn = await _db.connect();
    // httpfs est auto-chargé par DuckDB-Wasm au premier ATTACH https://.
    // READ_ONLY autorise la lecture concurrente par plages d'octets sans verrou.
    await _conn.query(`ATTACH '${url}' AS osint_db (READ_ONLY);`);
    await _conn.query(`USE osint_db;`);
  })();

  return _initPromise;
}

/**
 * Variante pour un fichier database.db protégé (Authorization: Bearer ...).
 * Le fichier est téléchargé en entier via fetch() puis monté dans le FS virtuel.
 * On perd le lazy-loading par plages, mais on gagne le contrôle d'accès.
 */
export async function initOsintDbWithAuth(
  url: string,
  headers: Record<string, string>
): Promise<void> {
  if (_initPromise) return _initPromise;

  _initPromise = (async () => {
    _db = await _instantiateEngine();

    const response = await fetch(url, { headers });
    if (!response.ok) {
      throw new Error(
        `Téléchargement échoué (${response.status} ${response.statusText})`
      );
    }
    const buffer = new Uint8Array(await response.arrayBuffer());
    await _db.registerFileBuffer("database.db", buffer);

    _conn = await _db.connect();
    await _conn.query(`ATTACH 'database.db' AS osint_db (READ_ONLY);`);
    await _conn.query(`USE osint_db;`);
  })();

  return _initPromise;
}

// ─── Helpers internes ─────────────────────────────────────────────────────────

function _escapeLike(term: string): string {
  return term.replace(/\\/g, "\\\\").replace(/%/g, "\\%").replace(/_/g, "\\_");
}

/**
 * Détecte le type probable d'une requête OSINT pour orienter la recherche.
 * Retourne la colonne exacte à utiliser si le terme ressemble à une valeur connue.
 */
function _detectType(
  term: string
): "email" | "ip" | "domain" | "hash" | "phone" | "username" | "generic" {
  const t = term.trim();
  if (/^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/.test(t)) return "email";
  if (/^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/.test(t)) return "ip";
  if (/^[0-9a-fA-F]{32,64}$/.test(t)) return "hash";
  if (/^(?:\+|00)[\d\s\-]{6,15}$/.test(t)) return "phone";
  if (/^[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/.test(t) && !t.includes("@")) return "domain";
  return "generic";
}

/** Clé de cache unique selon les filtres actifs. */
function _cacheKey(params: OsintSearchParams): string {
  const type = _detectType(params.term);
  return [
    type,
    params.filterDomain ? "dom" : "",
    params.filterIp ? "ip" : "",
    params.onlyWithPassword ? "pwd" : "",
  ]
    .filter(Boolean)
    .join("|");
}

/**
 * Construit le SQL optimisé selon la nature du terme et les filtres.
 *
 * Stratégie :
 *  - Terme email/ip/domain/hash/phone → égalité exacte sur la colonne indexée (ART).
 *  - Terme générique → ILIKE '%x%' sur username + ILIKE sur raw (vectorisé).
 *  - Filtres domain/ip additionnels → WHERE exact (ART) avant le scan ILIKE.
 *  - COUNT(*) OVER() pour le total en une seule passe (pas de requête COUNT séparée).
 */
function _buildSQL(params: OsintSearchParams): { sql: string; paramTypes: string[] } {
  const type = _detectType(params.term);
  const conditions: string[] = [];
  const paramTypes: string[] = []; // "exact" ou "like" pour construire les params à l'appel

  // ── Filtre principal sur le terme ──────────────────────────────────────────
  if (params.term.trim()) {
    switch (type) {
      case "email":
        conditions.push(`email = ?`);
        paramTypes.push("exact:email");
        break;
      case "ip":
        conditions.push(`ip = ?`);
        paramTypes.push("exact:ip");
        break;
      case "domain":
        conditions.push(`domain = ?`);
        paramTypes.push("exact:domain");
        break;
      case "hash":
        conditions.push(`hash_val = ?`);
        paramTypes.push("exact:hash");
        break;
      case "phone":
        conditions.push(`phone = ?`);
        paramTypes.push("exact:phone");
        break;
      case "generic":
      default:
        // Recherche large : username en ILIKE + raw en ILIKE
        conditions.push(`(username ILIKE ? ESCAPE '\\' OR raw ILIKE ? ESCAPE '\\')`);
        paramTypes.push("like", "like");
        break;
    }
  }

  // ── Filtres additionnels (colonnes indexées) ───────────────────────────────
  if (params.filterDomain) {
    conditions.push(`domain = ?`);
    paramTypes.push("exact:filterDomain");
  }
  if (params.filterIp) {
    conditions.push(`ip = ?`);
    paramTypes.push("exact:filterIp");
  }
  if (params.onlyWithPassword) {
    conditions.push(`password_set = TRUE`);
    // pas de paramètre supplémentaire
  }

  const whereClause =
    conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";

  const sql = `
    SELECT
      id, src, email, username, password_set,
      hash_val, domain, ip, phone, raw,
      COUNT(*) OVER() AS _total
    FROM records
    ${whereClause}
    ORDER BY
      CASE WHEN email IS NOT NULL THEN 0 ELSE 1 END,
      email NULLS LAST,
      username NULLS LAST
    LIMIT ? OFFSET ?;
  `;

  paramTypes.push("limit", "offset");
  return { sql, paramTypes };
}

async function _getOrCreateStmt(
  params: OsintSearchParams
): Promise<{ stmt: AsyncPreparedStatement; paramTypes: string[] }> {
  if (!_conn) {
    throw new Error(
      "DuckDB non initialisé. Appelez initOsintDb() avant toute recherche."
    );
  }
  const key = _cacheKey(params);
  const cached = _stmtCache.get(key);
  const { sql, paramTypes } = _buildSQL(params);
  if (cached) return { stmt: cached, paramTypes };

  const stmt = await _conn.prepare(sql);
  _stmtCache.set(key, stmt);
  return { stmt, paramTypes };
}

// ─── Recherche principale ─────────────────────────────────────────────────────

/**
 * Recherche paginée multi-champs dans la base OSINT.
 *
 * - Terme email / ip / domain / hash / phone → lookup exact indexé (sub-ms).
 * - Terme générique → ILIKE sur username + raw (scan vectorisé).
 * - Filtres domain/ip toujours en égalité exacte (index ART).
 *
 * @example
 *   await initOsintDb();
 *
 *   // Lookup exact par email
 *   const r1 = await osintSearch({ term: "alice@example.com" });
 *
 *   // Recherche par domaine
 *   const r2 = await osintSearch({ term: "gmail.com" });
 *
 *   // Recherche générique + filtre domaine
 *   const r3 = await osintSearch({ term: "alice", filterDomain: "example.com", limit: 50 });
 *
 *   // Enregistrements avec mot de passe exposé sur un domaine
 *   const r4 = await osintSearch({ term: "", filterDomain: "example.com", onlyWithPassword: true });
 */
export async function osintSearch({
  term,
  filterDomain,
  filterIp,
  onlyWithPassword = false,
  limit = 20,
  offset = 0,
}: OsintSearchParams): Promise<OsintSearchResponse> {
  const { stmt, paramTypes } = await _getOrCreateStmt({
    term, filterDomain, filterIp, onlyWithPassword, limit, offset,
  });

  const pattern = term.trim() ? `%${_escapeLike(term.trim())}%` : "%";
  const exactTerm = term.trim();

  // Construit le tableau de paramètres dans l'ordre des placeholders SQL
  const params: unknown[] = [];
  for (const pt of paramTypes) {
    switch (pt) {
      case "exact:email":
      case "exact:ip":
      case "exact:domain":
      case "exact:hash":
      case "exact:phone":
        params.push(exactTerm);
        break;
      case "exact:filterDomain":
        params.push(filterDomain!);
        break;
      case "exact:filterIp":
        params.push(filterIp!);
        break;
      case "like":
        params.push(pattern);
        break;
      case "limit":
        params.push(limit);
        break;
      case "offset":
        params.push(offset);
        break;
    }
  }

  const t0 = performance.now();
  const arrow = await stmt.query(...params);
  const tookMs = performance.now() - t0;

  const raw = arrow.toArray();
  const total = raw.length > 0 ? Number((raw[0].toJSON() as { _total: bigint })._total) : 0;

  const rows: OsintRecord[] = raw.map((r) => {
    const obj = r.toJSON() as OsintRecord & { _total: bigint };
    return {
      id: obj.id,
      src: obj.src,
      email: obj.email,
      username: obj.username,
      password_set: obj.password_set,
      hash_val: obj.hash_val,
      domain: obj.domain,
      ip: obj.ip,
      phone: obj.phone,
      raw: obj.raw,
    };
  });

  return { rows, total, tookMs };
}

// ─── Lookups ponctuels ultra-rapides (index ART) ──────────────────────────────

/** Trouve tous les enregistrements d'un email exact. Utilise l'index ART. */
export async function findByEmail(email: string): Promise<OsintRecord[]> {
  return _lookupExact("email", email);
}

/** Trouve tous les enregistrements d'une IP exacte. */
export async function findByIp(ip: string): Promise<OsintRecord[]> {
  return _lookupExact("ip", ip);
}

/** Trouve tous les enregistrements d'un domaine exact. */
export async function findByDomain(domain: string): Promise<OsintRecord[]> {
  return _lookupExact("domain", domain);
}

/** Trouve tous les enregistrements d'un hash exact. */
export async function findByHash(hash: string): Promise<OsintRecord[]> {
  return _lookupExact("hash_val", hash);
}

/** Trouve tous les enregistrements d'un username exact. */
export async function findByUsername(username: string): Promise<OsintRecord[]> {
  return _lookupExact("username", username);
}

async function _lookupExact(
  col: keyof OsintRecord,
  value: string,
  limitN = 500
): Promise<OsintRecord[]> {
  if (!_conn) throw new Error("DuckDB non initialisé.");
  const stmt = await _conn.prepare(
    `SELECT id, src, email, username, password_set, hash_val, domain, ip, phone, raw
     FROM records WHERE ${col} = ? LIMIT ${limitN};`
  );
  try {
    const result = await stmt.query(value);
    return result.toArray().map((r) => {
      const obj = r.toJSON() as OsintRecord;
      return {
        id: obj.id,
        src: obj.src,
        email: obj.email,
        username: obj.username,
        password_set: obj.password_set,
        hash_val: obj.hash_val,
        domain: obj.domain,
        ip: obj.ip,
        phone: obj.phone,
        raw: obj.raw,
      };
    });
  } finally {
    await stmt.close();
  }
}

// ─── Statistiques rapides ─────────────────────────────────────────────────────

export interface OsintStats {
  total: number;
  withEmail: number;
  withPassword: number;
  uniqueDomains: number;
  uniqueIps: number;
  sources: string[];
}

/** Statistiques globales de la base (utile pour le dashboard). */
export async function getStats(): Promise<OsintStats> {
  if (!_conn) throw new Error("DuckDB non initialisé.");
  const result = await _conn.query(`
    SELECT
      COUNT(*)                                AS total,
      COUNT(email)                            AS with_email,
      SUM(CASE WHEN password_set THEN 1 ELSE 0 END) AS with_password,
      COUNT(DISTINCT domain)                  AS unique_domains,
      COUNT(DISTINCT ip)                      AS unique_ips
    FROM records;
  `);
  const row = result.toArray()[0]?.toJSON() as {
    total: bigint; with_email: bigint; with_password: bigint;
    unique_domains: bigint; unique_ips: bigint;
  };

  const srcResult = await _conn.query(
    `SELECT DISTINCT src FROM records WHERE src IS NOT NULL ORDER BY src LIMIT 200;`
  );
  const sources = srcResult.toArray().map(
    (r) => (r.toJSON() as { src: string }).src
  );

  return {
    total: Number(row.total),
    withEmail: Number(row.with_email),
    withPassword: Number(row.with_password),
    uniqueDomains: Number(row.unique_domains),
    uniqueIps: Number(row.unique_ips),
    sources,
  };
}

// ─── Nettoyage ────────────────────────────────────────────────────────────────

export async function closeOsintDb(): Promise<void> {
  for (const stmt of _stmtCache.values()) {
    await stmt.close();
  }
  _stmtCache.clear();
  if (_conn) await _conn.close();
  if (_db) await _db.terminate();
  _conn = null;
  _db = null;
  _initPromise = null;
}

// ─── Utilitaire debounce (pour la recherche live) ─────────────────────────────

export function debounce<Args extends unknown[]>(
  fn: (...args: Args) => void,
  delayMs = 200
): (...args: Args) => void {
  let timer: ReturnType<typeof setTimeout> | undefined;
  return (...args: Args) => {
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => fn(...args), delayMs);
  };
}

// ─── Auto-détection du type de requête (utile pour l'UI) ─────────────────────

export { _detectType as detectOsintType };
