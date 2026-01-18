# STACK TECHNOLOGIQUE — SecureTrack

## Backend

### Python 3.11+ + Django 4.2+ LTS

**Choix :** Oui

**Justification :**
- ✅ Framework web mature et sécurisé par défaut
- ✅ ORM (Django ORM) protège contre injections SQL
- ✅ Built-in CSRF protection via tokens
- ✅ Intégration authentification/sessions robuste
- ✅ Grosse communauté + beaucoup de librairies security
- ✅ Facile à apprendre et maintenir
- ✅ Django Admin pour gestion de base

**Alternatives considérées :**
- FastAPI : plus moderne, mais moins "batteries included"
- Flask : trop minimaliste pour sécurité
- ASP.NET : technologie Microsoft, moins familiaire

---

## Base de données

### PostgreSQL 14+

**Choix :** Oui

**Justification :**
- ✅ SGBD relationnel mûr et fiable
- ✅ Support ACID transactions (backup/restore atomique)
- ✅ Intégration Django native
- ✅ Permet triggers (audit logs automatiques)
- ✅ Chiffrement données en transit
- ✅ Bonnes perfs, scalable

**Alternatives :**
- MySQL : OK mais PostgreSQL mieux pour audit logs
- MongoDB : NoSQL, moins adapté pour sécurité (pas de transactions)
- SQLite : OK pour dev local, pas prod

---

## Conteneurisation

### Docker + Docker Compose

**Choix :** Oui

**Justification :**
- ✅ Environnement reproductible (dev = prod)
- ✅ Isolation du code + DB + dependencies
- ✅ Facile déploiement sur serveur
- ✅ Intégrable en CI/CD
- ✅ Permet tests en parallèle (chaque test = container)

**Fichier : Dockerfile**
```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy code
COPY . .

# Run Django
CMD ["gunicorn", "project.wsgi:application", "--bind", "0.0.0.0:8000"]
