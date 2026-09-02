# SentinelAgent Autonomous SOC System Launcher
Write-Host "=========================================================" -ForegroundColor Cyan
Write-Host "   SentinelAgent: Autonomous SOC Multi-Agent System       " -ForegroundColor Yellow
Write-Host "=========================================================" -ForegroundColor Cyan

$WorkspaceRoot = $PSScriptRoot
$BackendDir = Join-Path $WorkspaceRoot "backend"
$FrontendDir = Join-Path $WorkspaceRoot "frontend"

# Step 1: Ensure Model Exists
$ModelFile = Join-Path $BackendDir "app\ml\model.joblib"
if (-not (Test-Path $ModelFile)) {
    Write-Host "[*] Training initial Scikit-Learn SOC Classifier..." -ForegroundColor Cyan
    Set-Location $BackendDir
    python app/ml/classifier.py
}

# Step 2: Launch Backend
Write-Host "[*] Launching FastAPI Agentic Core on http://localhost:8000..." -ForegroundColor Green
$BackendProcess = Start-Process -FilePath "python" -ArgumentList "-m uvicorn app.main:app --host 0.0.0.0 --port 8000" -WorkingDirectory $BackendDir -PassThru

# Step 3: Launch Frontend
Write-Host "[*] Launching React SOC Dashboard on http://localhost:5173..." -ForegroundColor Green
$FrontendProcess = Start-Process -FilePath "npm.cmd" -ArgumentList "run dev" -WorkingDirectory $FrontendDir -PassThru

Start-Sleep -Seconds 3

# Step 4: Open Browser
Write-Host "[✓] System Ready! Opening SOC Dashboard in browser..." -ForegroundColor Cyan
Start-Process "http://localhost:5173"

Write-Host "`n[i] Press CTRL+C or close this window to terminate SentinelAgent." -ForegroundColor Yellow
Wait-Process -Id $BackendProcess.Id, $FrontendProcess.Id
