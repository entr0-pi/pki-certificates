@echo off
REM Start the PKI Management Web Application
cd /d "%~dp0.."
echo ====================================
echo PKI Management Web Application
echo ====================================
echo.
echo Starting FastAPI server...
echo Access the application at: http://localhost:8000
echo Press Ctrl+C to stop the server
echo.

echo Ensuring database is initialized...
python scripts\init_db.py
if errorlevel 1 (
  echo Database initialization failed.
  echo Run: python scripts\init_db.py --recreate-invalid
  exit /b 1
)

python backend\app.py
