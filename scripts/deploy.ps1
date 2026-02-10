# 🚀 SecureTrack Production Deployment Script

$ErrorActionPreference = "Stop"

Write-Host "🚀 Deploiement SecureTrack Production..."

# Load .env.production
if (-not (Test-Path ".env.production")) {
    Write-Host "❌ Erreur: .env.production non trouve"
    exit 1
}

Write-Host "Loading environment variables..."
Get-Content .env.production | ForEach-Object {
    if ($_ -match "^\s*([^=]+)=(.*)$") {
        [System.Environment]::SetEnvironmentVariable($matches[1].Trim(), $matches[2].Trim(), [System.EnvironmentVariableTarget]::Process)
    }
}

# Pull latest version
Write-Host "📥 Pulling latest code..."
git pull origin main

# Build images
Write-Host "🐳 Building Docker images..."
docker-compose -f docker-compose.prod.yml build --no-cache
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Docker build failed"
    exit 1
}

# Start services
Write-Host "🚀 Starting services..."
docker-compose -f docker-compose.prod.yml up -d
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Failed to start services"
    exit 1
}

# Run migrations
Write-Host "🔄 Running migrations..."
docker-compose -f docker-compose.prod.yml exec -T web python src/manage.py migrate
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Migrations failed"
    exit 1
}

# Collect static files
Write-Host "📦 Collecting static files..."
docker-compose -f docker-compose.prod.yml exec -T web python src/manage.py collectstatic --noinput
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Collectstatic failed"
    exit 1
}

# Health check
Write-Host "🏥 Running health checks..."
Start-Sleep -Seconds 5
docker-compose -f docker-compose.prod.yml exec -T web curl -f http://localhost:8000/api/health/ 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Health check failed"
    exit 1
}

Write-Host "✅ Deploiement reussi!"
