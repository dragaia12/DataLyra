@echo off
chcp 65001 >nul
title OSINT HUB Backend v4.1 (corrige)
echo ============================================
echo   OSINT HUB Backend v4.1 - Demarrage
echo ============================================
echo.

:: Verifier Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERREUR] Python 3.10+ requis.
    echo Telecharger : https://www.python.org/downloads/
    pause
    exit /b 1
)

:: Installer les dependances
echo [1/2] Installation des dependances...
pip install -r "%~dp0requirements.txt" --quiet

:: Creer le dossier pour vos donnees s'il n'existe pas
if not exist "%~dp0osint_data" (
    mkdir "%~dp0osint_data"
    echo.
    echo [INFO] Dossier "osint_data" cree.
    echo        ^>^> Mettez vos fichiers (.csv .json .jsonl .txt .sql) DEDANS.
)

echo.
echo [2/2] Demarrage du serveur sur http://localhost:8765
echo.
echo   - Mettez vos donnees dans : %~dp0osint_data
echo   - Le scan demarre automatiquement au lancement
echo   - Ctrl+C pour arreter proprement.
echo.

python "%~dp0server_v3.py"
pause
