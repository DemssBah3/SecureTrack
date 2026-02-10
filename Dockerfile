# ============ Stage 1: Builder ============
FROM python:3.12-slim as builder

WORKDIR /app

# Installer les dépendances système nécessaires pour build
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copier requirements et installer Python packages
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# ============ Stage 2: Runtime ============
FROM python:3.12-slim

WORKDIR /app

# Installer seulement les dépendances runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    postgresql-client \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Créer utilisateur non-root
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Copier Python packages depuis builder
COPY --from=builder /root/.local /home/appuser/.local

# Copier code application
COPY src /app/src

# Créer répertoires nécessaires
RUN mkdir -p /app/logs /app/staticfiles /app/media && \
    chown -R appuser:appuser /app

# Définir variables d'environnement
ENV PATH=/home/appuser/.local/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app/src

# Exposer port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/health/ || exit 1

# Utiliser utilisateur non-root
USER appuser

# Démarrer application
CMD ["gunicorn", \
     "--bind", "0.0.0.0:8000", \
     "--workers", "4", \
     "--worker-class", "sync", \
     "--worker-tmp-dir", "/dev/shm", \
     "--max-requests", "1000", \
     "--max-requests-jitter", "100", \
     "--timeout", "60", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "securetrack.wsgi:application"]
