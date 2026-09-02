@echo off
title SentinelAgent - Autonomous SOC Multi-Agent System
color 0B
echo =========================================================
echo    SentinelAgent: Autonomous SOC Multi-Agent System      
echo =========================================================
echo.

cd /d "%~dp0backend"
if not exist "app\ml\model.joblib" (
    echo [*] Training initial Scikit-Learn SOC Classifier...
    python app/ml/classifier.py
)

echo [*] Starting FastAPI Backend on http://localhost:8000...
start "SentinelAgent Backend" cmd /k "cd /d %~dp0backend && python -m uvicorn app.main:app --host 0.0.0.0 --port 8000"

echo [*] Starting React Frontend on http://localhost:5173...
start "SentinelAgent Frontend" cmd /k "cd /d %~dp0frontend && npm run dev"

timeout /t 3 >nul
echo [✓] Launching browser...
start http://localhost:5173

echo.
echo SentinelAgent is running!
echo Backend:  http://localhost:8000
echo Frontend: http://localhost:5173
echo.
pause
