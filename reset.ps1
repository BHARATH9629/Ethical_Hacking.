# Resets the demo to a clean state between runs.
Write-Host "Resetting defender in-memory state..."
try {
    Invoke-RestMethod -Uri "http://localhost:8000/reset" -Method Post -ErrorAction Stop | Out-Null
} catch {
    Write-Host "  (defender not reachable, skipping)"
}

Write-Host "Restarting LocalStack container (fresh state, PERSISTENCE=0)..."
docker-compose down
docker-compose up -d

Write-Host "Waiting for LocalStack to become healthy..."
$attempts = 0
do {
    Start-Sleep -Seconds 2
    $attempts++
    try {
        $health = Invoke-RestMethod -Uri "http://localhost:4566/_localstack/health" -ErrorAction Stop
        $ready = $true
    } catch {
        $ready = $false
    }
} while (-not $ready -and $attempts -lt 30)

if (-not $ready) {
    Write-Host "LocalStack did not become healthy in time. Check docker logs."
    exit 1
}

Write-Host "Re-seeding environment..."
python seed/seed_environment.py

Write-Host "Removing local attacker artifacts..."
Remove-Item -Path "attacker/.leaked_creds" -ErrorAction SilentlyContinue
Remove-Item -Path "attacker/downloaded_config.yaml.bak" -ErrorAction SilentlyContinue

Write-Host "Reset complete. Ready for the next run."
