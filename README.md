# OSINT HUB — Backend

## Fichiers

| Fichier | Rôle |
|---|---|
| `server_v3.py` | Serveur FastAPI WebSocket (Option A uniquement) |
| `reset_and_import.py` | Import rapide de vos fichiers dans DuckDB |
| `build_database.py` | ⭐ Génère `database.db` pour l'Option B (DuckDB-Wasm) |
| `duckdb-client.ts` | ⭐ À copier dans le frontend (Option B) |
| `requirements.txt` | Dépendances Python |
| `start.bat` | Lancement rapide Windows (Option A) |
| `render.yaml` | Déploiement Render.com (Option A) |

## Option B — Frontend autonome (recommandée)

```bash
# 1. Installer duckdb
pip install duckdb==1.5.4 --break-system-packages

# 2. Mettre vos fichiers sources dans osint_data/
#    Formats supportés : .json .jsonl .csv .tsv .txt

# 3. Générer la base statique
python3 build_database.py --input "./osint_data/**/*" --output database.db

# 4. Copier database.db dans le frontend
cp database.db ../frontend/public/
```

## Option A — Backend FastAPI (recherche WebSocket)

```bash
# 1. Installer les dépendances
pip install -r requirements.txt

# 2. Mettre vos fichiers dans osint_data/

# 3. Importer (optionnel : le serveur importe aussi au démarrage)
python3 reset_and_import.py

# 4. Lancer le serveur
python3 server_v3.py
# ou sous Windows :
start.bat
```

## Compatibilité DuckDB

`database.db` doit être généré avec la même version que DuckDB-Wasm côté frontend.
Au moment de la rédaction : **DuckDB 1.5.x**.

```bash
pip install duckdb==1.5.4 --break-system-packages
```

Vérifiez la version de `@duckdb/duckdb-wasm` sur :
https://github.com/duckdb/duckdb-wasm
