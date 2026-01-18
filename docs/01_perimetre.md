# PÉRIMÈTRE — SecureTrack

## IN SCOPE (On le fait)

### Authentification et Sécurité
- ✅ Inscription avec email + mot de passe
- ✅ Login / Logout sécurisés
- ✅ Hachage des mots de passe (Argon2id)
- ✅ 2FA TOTP (authenticator app)
- ✅ Codes de secours (backup codes)
- ✅ Reset de mot de passe
- ✅ Rate limiting sur les tentatives de login
- ✅ Journalisation des événements d'auth

### Gestion des tickets et projets
- ✅ Modèle Ticket (titre, description, statut, priorité)
- ✅ Modèle Projet (nom, description)
- ✅ CRUD de base (Create, Read, Update, Delete)
- ✅ Interface web simple (Django templates)
- ✅ Validations d'entrée

### Contrôles d'accès
- ✅ Rôles : User, Manager, Admin
- ✅ RBAC (Role-Based Access Control)
- ✅ Contrôles d'accès au niveau des objets
- ✅ Tests d'autorisation

### Protection web
- ✅ CSRF tokens sur tous les formulaires
- ✅ Protection XSS
- ✅ En-têtes de sécurité (CSP, HSTS, X-Frame-Options, etc.)
- ✅ Pièces jointes sécurisées (validation types/tailles)

### Tests et qualité
- ✅ Tests unitaires + tests d'intégration
- ✅ SAST (Bandit, SonarQube ou similaire)
- ✅ DAST (OWASP ZAP)
- ✅ Scan de dépendances

### DevOps et déploiement
- ✅ Docker + Docker Compose
- ✅ CI/CD pipeline (GitHub Actions)
- ✅ Nginx comme reverse proxy
- ✅ PostgreSQL comme base de données
- ✅ Logs structurés et audit trail

### Documentation
- ✅ Rapport final d'analyse de sécurité
- ✅ DFD (Data Flow Diagram)
- ✅ Modèle de menaces (STRIDE)
- ✅ Mapping OWASP Top 10 + ASVS
- ✅ Guide d'exploitation/déploiement

---

## OUT OF SCOPE (On ne le fait pas)

- ❌ Paiement/facturation
- ❌ Notifications par email
- ❌ Intégration API externe
- ❌ Scalabilité multi-serveur (seulement local + staging)
- ❌ Application mobile
- ❌ Chiffrement end-to-end des tickets
- ❌ Machine learning / IA
- ❌ Support multilingue
- ❌ Real-time collaboration (WebSockets)

---

## Justification du périmètre

Le focus est clairement sur la **sécurité applicative** et les **bonnes pratiques web**, 
pas sur la complexité métier. L'app est volontairement simple pour laisser place 
à l'apprentissage des contrôles de sécurité (auth, RBAC, CSRF, XSS, audit, etc.).
