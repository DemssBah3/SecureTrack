# Image de base : Python 3.11
FROM python:3.11-slim

# Définir le répertoire de travail dans le conteneur
WORKDIR /app

# Installer dépendances système (nécessaires pour certains packages Python)
RUN apt-get update && apt-get install -y \
    postgresql-client \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copier requirements.txt
COPY requirements.txt .

# Installer dépendances Python
# --no-cache-dir : économise de l'espace disque
RUN pip install --no-cache-dir -r requirements.txt

# Copier le code source
COPY . .

# Port par défaut
EXPOSE 8000

# Commande de démarrage (overridable par docker-compose)
CMD ["gunicorn", "securetrack.wsgi:application", "--bind", "0.0.0.0:8000"]
