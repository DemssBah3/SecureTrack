# Stage 1: Builder
FROM python:3.11-slim as builder

WORKDIR /app

# Installer les dépendances de build
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copier requirements
COPY requirements.txt .

# Créer virtualenv en stage builder
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --no-cache-dir -r requirements.txt

# Stage 2: Runtime
FROM python:3.11-slim

# Metadata labels (SBOM)
LABEL org.opencontainers.image.title="SecureTrack"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.vendor="SecureTrack"
LABEL org.opencontainers.image.licenses="MIT"

# Créer utilisateur non-root
RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /app

# Installer runtime deps seulement
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copier venv du builder
COPY --from=builder /opt/venv /opt/venv

# Copier code application
COPY . .

# Fixer permissions
RUN chown -R appuser:appuser /app

# Définir user non-root
USER appuser

# Définir PATH
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DEBUG=False

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health/ || exit 1

# Port d'écoute
EXPOSE 8000

# CMD: gunicorn (au lieu de runserver)
CMD ["gunicorn", "securetrack.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "4", "--timeout", "60"]
