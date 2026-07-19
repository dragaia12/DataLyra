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

print("🏗️ Création de la table records avec Adresse par défaut...")
conn.execute("""
    CREATE TABLE IF NOT EXISTS records (
        id               UBIGINT PRIMARY KEY,
        src              VARCHAR,
        email            VARCHAR,
        username         VARCHAR,
        password         VARCHAR,
        password_set     BOOLEAN,
        hash_val         VARCHAR,
        domain           VARCHAR,
        ip               VARCHAR,
        phone            VARCHAR,
        firstname        VARCHAR,
        lastname         VARCHAR,
        siret            VARCHAR,
        address          VARCHAR,  -- Ajouté en colonne standard par défaut
        extra_attributes JSON,     -- Pour le reste des imprévus (tokens, etc.)
        raw              VARCHAR
    )
""")

fichiers = ["Avast_2014_400k.json", "brazzers com April 2013.json", "GTA5Base.com .json"]

for f in fichiers:
    path = f"D:/osint_data/{f}"
    if not os.path.exists(path):
        continue
        
    print(f"⚡ Ingestion Brute Force de {f}...")
    try:
        conn.execute(f"""
            INSERT INTO records
            SELECT
                hash('{f}' || line || CAST(row_number() OVER() AS VARCHAR))::UBIGINT AS id,
                '{f}' AS src,
                
                -- Extraction Email & Domaine
                regexp_extract(line, '[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{{2,}}', 0) AS email,
                regexp_extract(line, '@([a-zA-Z0-9.\\-]+\\.[a-zA-Z]{{2,}})', 1) AS domain,
                
                -- Extraction Username
                coalesce(
                    regexp_extract(line, '"(?:username|login)"\\s*:\\s*"([^"]+)"', 1),
                    regexp_extract(line, '(?:^|,|;|\\|)(?:user|pseudo|login)[:=]([^,;|\\s]+)', 1)
                ) AS username,
                
                -- Extraction Mot de Passe
                coalesce(
                    regexp_extract(line, '"(?:password|pass|pwd)"\\s*:\\s*"([^"]+)"', 1),
                    regexp_extract(line, '(?:^|,|;|\\|)(?:password|pass|pwd|mdp)[:=]([^,;|\\s]+)', 1)
                ) AS password,
                (line LIKE '%pass%' OR line LIKE '%pwd%' OR line LIKE '%mdp%') AS password_set,
                
                -- Extraction Hash
                regexp_extract(line, '\\b([a-fA-F0-9]{{32}}|[a-fA-F0-9]{{40}}|[a-fA-F0-9]{{64}})\\b', 0) AS hash_val,
                
                -- Extraction IP & Téléphone
                regexp_extract(line, '\\b(?:[0-9]{{1,3}}\\.){{3}}[0-9]{{1,3}}\\b', 0) AS ip,
                regexp_extract(line, '(?:\\+33|0)[1-9](?:[\\s.-]*[0-9]{{2}}){{4}}\\b', 0) AS phone,
                
                -- Extraction Prénom & Nom
                regexp_extract(line, '"(?:firstname|prenom)"\\s*:\\s*"([^"]+)"', 1) AS firstname,
                regexp_extract(line, '"(?:lastname|nom)"\\s*:\\s*"([^"]+)"', 1) AS lastname,
                
                -- Extraction SIRET
                regexp_extract(line, '\\b[0-9]{{14}}\\b', 0) AS siret,
                
                -- HARMONISATION DE L'ADRESSE (Fouille large : adresse, address, addr, adr)
                coalesce(
                    regexp_extract(line, '"(?:address|adresse|addr|adr)"\\s*:\\s*"([^"]+)"', 1),
                    regexp_extract(line, '(?:^|,|;|\\|)(?:address|adresse|addr|adr)[:=]([^,;|\\|]+)', 1)
                ) AS address,
                
                -- Reste des attributs au format JSON (ex: tokens, id d'origine...)
                to_json(json_object(
                    'token', regexp_extract(line, '"token"\\s*:\\s*"([^"]+)"', 1),
                    'uid_origine', regexp_extract(line, '"id"\\s*:\\s*([0-9]+)', 1)
                )) AS extra_attributes,
                
                substring(line, 1, 500) AS raw
            FROM read_csv('{path}', columns={{'line':'VARCHAR'}}, header=false, ignore_errors=true)
            WHERE trim(line) != '' AND email IS NOT NULL
            ON CONFLICT (id) DO NOTHING;
        """)
        print(f"✅ {f} avalé et structuré (Adresses harmonisées) !")
    except Exception as e:
        print(f"❌ Erreur sur {f}: {e}")

print("⚡ Génération des index ART flash...")
for col in ("email", "username", "domain", "phone", "lastname", "siret", "address"):
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{col} ON records({col})")

conn.close()
print("🎉 Base de données entièrement reconstruite !")