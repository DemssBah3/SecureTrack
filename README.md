# SecureTrack

Conception et sécurisation d'une application web de gestion de tickets selon les standards OWASP.

## 🎯 Objectif du projet

SecureTrack est une application de **gestion de tickets** développée avec un **focus cybersécurité**. Le projet respecte les standards **OWASP Top 10** et **OWASP ASVS niveau 1** (avec sous-ensemble niveau 2 pour éléments critiques).

**Cours :** 8INF309 - Projet intégrateur  
**Université :** UQAC  
**Professeur :** Jimmy Girard-Nault  
**Étudiants :** Aboubacar Demba Bah, Mamadou Ciré Bah  
**Semestre :** Hiver 2026 (14 semaines)

---

## 🚀 Stack technologique

- **Backend :** Python 3.11 + Django 4.2+ LTS
- **Base de données :** PostgreSQL 14+
- **Conteneurisation :** Docker + Docker Compose
- **Serveur web :** Nginx + Gunicorn
- **Authentification :** Argon2id + TOTP
- **Tests sécurité :** Bandit (SAST) + OWASP ZAP (DAST)
- **CI/CD :** GitHub Actions

---

## 📋 Structure du projet

SecureTrack/ 
├── docs/ 
    │ ├── 01_perimetre.md # Périmètre IN/OUT scope 
    │ ├── 02_threat_model.md # Menaces STRIDE v1 
    │ ├── 03_dfd_details.md # Data Flow Diagram expliqué 
    │ ├── 04_stack_justification.md # Choix technologiques 
    │ ├── 05_timeline.md # Planning 14 semaines 
    │ ├── 06_user_stories.md # 27 user stories 
    │ └── dfd-v1.png # Diagramme DFD visuel 
├── src/ 
    │ └── (code Django sera ici S2+)
├── tests/ │ └── (tests unitaires S3+) 
├── docker-compose.yml # Setup local 
├── Dockerfile # Image app 
├── requirements.txt # Dépendances Python 
├── .gitignore # Fichiers à ignorer 
└── README.md # Ce fichier

🔐 Fonctionnalités de sécurité
✅ Authentification robuste : Argon2id + 2FA TOTP + codes de secours
✅ Contrôles d'accès : RBAC (user, manager, admin)
✅ Protections web : CSRF, XSS, en-têtes sécurité (CSP, HSTS)
✅ Audit trail : Journalisation complète des événements
✅ Tests de sécurité : SAST (Bandit) + DAST (ZAP) automatisés
✅ DevSecOps : CI/CD pipeline avec scans de dépendances

📅 Timeline
Semaines	Milestone	Livrables
1-2	Setup + Cadrage	Périmètre, DFD, menaces, repo, CI/CD
3-4	Auth + 2FA	Signup, login, TOTP démontrables
5-6	Tickets + RBAC	CRUD tickets, gestion rôles, tests accès
7-8	Hardening + DAST	En-têtes sécurité, audit logs, ZAP v1
9-10	DevSecOps	CI/CD avancée, Trivy, staging live
11-12	Revue + fixes	Pentest interne, 0 High/Critical
13-14	Rapport + soutenance	Documentation complète, présentation
🛠️ Installation locale (S2+)
Copy# Cloner le repo
git clone https://github.com/tonUsername/SecureTrack.git
cd SecureTrack

# Setup avec Docker Compose
docker-compose up -d

# La app sera accessible sur http://localhost:8000
📊 Mapping de sécurité
OWASP Top 10 2021 : Toutes les 10 catégories adressées
OWASP ASVS v4.0 : Niveau 1 complet + sous-ensemble niveau 2
Voir le rapport final pour détails.

📝 Documentation
📄 /docs/01_perimetre.md : Périmètre du projet
📄 /docs/02_threat_model.md : Modèle de menaces STRIDE
📄 /docs/03_dfd_details.md : Flux de données détaillés
📄 /docs/04_stack_justification.md : Justification des technos
📄 /docs/05_timeline.md : Planning + jalons
📄 /docs/06_user_stories.md : 27 user stories avec 

🔄 Processus de développement
Créer une branche : git checkout -b feature/US-XXX
Développer avec tests
Commit : messages explicites
Push et créer Pull Request
Code review (si en équipe)
Merge sur develop ou main
CI/CD pipeline s'exécute automatiquement
📞 Contact
Prof : Jimmy Girard-Nault (jgnault@uqac.ca)
Repo : GitHub - SecureTrack
Issues : Utiliser GitHub Issues pour tracker bugs/features