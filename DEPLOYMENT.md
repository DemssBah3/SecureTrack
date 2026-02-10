# 🚀 Production Deployment Guide - SecureTrack

## Prerequisites

- Docker & Docker Compose installed
- SSL certificates (cert.pem, key.pem in ./certs/)
- Production server with ports 80, 443 open
- Git access to repository

## Environment Setup

### 1. Copy .env.production and Edit

```bash
cp .env.production .env.production.local
# Edit with real values:
# - SECRET_KEY: Generate with: python -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())'
# - ALLOWED_HOSTS: Your domain
# - DATABASE_PASSWORD: Strong password
# - REDIS_PASSWORD: Strong password
