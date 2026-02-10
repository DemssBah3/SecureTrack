# 🏥 SecureTrack Health Check

Write-Host "🏥 SecureTrack Health Check..."

# Load environment variables
if (Test-Path ".env.production") {
    Get-Content .env.production | ForEach-Object {
        if ($_ -match "^\s*([^=]+)=(.*)$") {
            [System.Environment]::SetEnvironmentVariable($matches[1].Trim(), $matches[2].Trim(), [System.EnvironmentVariableTarget]::Process)
        }
    }
}

# PostgreSQL Check
Write-Host "Checking PostgreSQL..."
try {
    $result = docker-compose -f docker-compose.prod.yml exec -T postgres pg_isready -U $env:DB_USER 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ PostgreSQL OK"
    } else {
        Write-Host "❌ PostgreSQL FAILED"
    }
} catch {
    Write-Host "❌ PostgreSQL FAILED - $_"
}

# Redis Check
Write-Host "Checking Redis..."
try {
    $result = docker-compose -f docker-compose.prod.yml exec -T redis redis-cli -a $env:REDIS_PASSWORD ping 2>&1
    if ($result -like "*PONG*") {
        Write-Host "✅ Redis OK"
    } else {
        Write-Host "❌ Redis FAILED"
    }
} catch {
    Write-Host "❌ Redis FAILED - $_"
}

# Django Health Endpoint Check
Write-Host "Checking Django health endpoint..."
try {
    $response = curl -s http://localhost:8000/api/health/ 2>&1
    if ($response -like '*"status":"ok"*') {
        Write-Host "✅ Django OK"
    } else {
        Write-Host "❌ Django FAILED"
    }
} catch {
    Write-Host "❌ Django FAILED - $_"
}

# Nginx Check
Write-Host "Checking Nginx..."
try {
    $response = curl -s -I http://localhost/api/health/ 2>&1
    if ($response -like "*200*") {
        Write-Host "✅ Nginx OK"
    } else {
        Write-Host "❌ Nginx FAILED"
    }
} catch {
    Write-Host "❌ Nginx FAILED - $_"
}

Write-Host "✅ Health check completed!"
