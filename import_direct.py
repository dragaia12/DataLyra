import duckdb
import os

DB_PATH = "osint_master.duckdb"

print("🧹 Nettoyage ultra-rapide...")
if os.path.exists(DB_PATH):
    try: os.remove(DB_PATH)
    except: pass

conn = duckdb.connect(DB_PATH, config={
    "threads": 8,
    "memory_limit": "12GB"
})

conn.execute("""
    CREATE TABLE IF NOT EXISTS records (
        id           UBIGINT PRIMARY KEY,
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

fichiers = ["Avast_2014_400k.json", "brazzers com April 2013.json", "GTA5Base.com .json"]

for f in fichiers:
    path = f"D:/osint_data/{f}"
    if not os.path.exists(path):
        continue
        
    print(f"⚡ Ingestion Brute Force de {f}...")
    try:
        # On traite TOUS les fichiers comme du texte brut.
        # On extrait les emails et les domaines instantanément via Regex hyper optimisée.
        conn.execute(f"""
            INSERT INTO records
            SELECT
                hash('{f}' || line || CAST(row_number() OVER() AS VARCHAR))::UBIGINT AS id,
                '{f}' AS src,
                regexp_extract(line, '[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{{2,}}', 0) AS email,
                NULL AS username,
                (line LIKE '%pass%' OR line LIKE '%pwd%') AS password_set,
                NULL AS hash_val,
                regexp_extract(line, '@([a-zA-Z0-9.\\-]+\\.[a-zA-Z]{{2,}})', 1) AS domain,
                regexp_extract(line, '\\b(?:[0-9]{{1,3}}\\.){{3}}[0-9]{{1,3}}\\b', 0) AS ip,
                NULL AS phone,
                substring(line, 1, 500) AS raw
            FROM read_csv('{path}', columns={{'line':'VARCHAR'}}, header=false, ignore_errors=true)
            WHERE trim(line) != '' AND email IS NOT NULL
            ON CONFLICT (id) DO NOTHING;
        """)
        print(f"✅ {f} avalé !")
    except Exception as e:
        print(f"❌ Erreur sur {f}: {e}")

print("⚡ Génération des index ART flash...")
for col in ("email", "domain"):
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{col} ON records({col})")

conn.close()
print("🎉 Terminé en un temps record ! Tu peux lancer server_v3.py")