@echo off
title PrivyScan - Privacy Contradiction Finder
color 0A

echo.
echo  ========================================
echo   PrivyScan - Privacy Contradiction Finder
echo   Starting your web app...
echo  ========================================
echo.

cd /d "%~dp0"

echo  [1/2] Activating Python environment...
call .venv\Scripts\activate.bat

echo  [2/2] Launching Streamlit Web App...
echo.
echo  Your browser will open at: http://localhost:8501
echo  Press Ctrl+C to stop the server.
echo.

start "" http://localhost:8501
python -m streamlit run app.py --server.port 8501

pause
