@echo off
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo Virtualenv not found. Create it first:
    echo   python -m venv .venv
    echo   .venv\Scripts\activate
    echo   pip install -r requirements.txt
    pause
    exit /b 1
)

echo Starting IOC Triage Tool at http://localhost:8501
echo Close this window to stop the app.
echo.

".venv\Scripts\python.exe" -m streamlit run ui_app.py --server.headless false
if errorlevel 1 pause
