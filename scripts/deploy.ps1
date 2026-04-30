$ErrorActionPreference = "Stop"

Write-Host "Logging into Railway..."
railway login

Write-Host "Linking project..."
railway link

Write-Host "Running database migrations..."
railway run flask --app run.py db upgrade

Write-Host "Deployment helper completed."
