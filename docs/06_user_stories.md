# BACKLOG INITIAL — SecureTrack

## Format

Chaque US : `As a [who], I want [what], so that [why]`

Chaque US aura :
- **ID** : US-XX
- **Titre** : résumé court
- **Description** : scénario détaillé
- **Priorité** : Critique / Haute / Moyenne / Basse
- **Semaine** : quand implémenter
- **Tests** : comment vérifier que c'est bon

---

## BLOC 1 : AUTHENTIFICATION (S3-S4)

### US-001 : Inscription utilisateur

**Titre :** L'utilisateur peut créer un compte

**Description :**
- L'utilisateur accède à `/register`
- Entre email + mot de passe + confirmation mdp
- Valider : email format, mdp force (12+ chars, majuscules, chiffres, caractères spéciaux)
- Créer user en DB avec mdp hashé (Argon2id)
- Redirection vers login avec message "Inscription réussie"
- Audit log : `user_created`

**Priorité :** Critique

**Semaine :** S3

**Tests :**
- ✅ Inscription valide → user créé
- ✅ Email invalide → erreur
- ✅ Mdp faible → erreur
- ✅ Email déjà existant → erreur
- ✅ Hash Argon2id en DB (jamais mdp brut)

---

### US-002 : Login utilisateur

**Titre :** L'utilisateur peut se connecter

**Description :**
- Accès `/login`
- Entre email + mdp
- Vérifier : email existe, hash mdp correspond
- Créer session sécurisée (token aléatoire)
- Cookies : HttpOnly, Secure, SameSite=Strict
- Redirection vers dashboard
- Audit log : `login_success` ou `login_failed`

**Priorité :** Critique

**Semaine :** S3

**Tests :**
- ✅ Login valide → session créée
- ✅ Mdp incorrect → erreur (sans révéler si email existe)
- ✅ Email inexistant → erreur générique
- ✅ Rate limiting : 5 tentatives max par 15 min → 429 Too Many Requests
- ✅ Cookie sécurisé (HttpOnly flag)

---

### US-003 : Logout utilisateur

**Titre :** L'utilisateur peut se déconnecter

**Description :**
- Bouton "Logout" dans UI
- POST `/logout`
- Supprimer session de la DB
- Supprimer cookie (Set-Cookie avec Max-Age=0)
- Redirection vers login
- Audit log : `logout`

**Priorité :** Critique

**Semaine :** S3

**Tests :**
- ✅ Logout détruit session
- ✅ Cookie expiré
- ✅ Utilisateur ne peut pas accéder /dashboard après logout

---

### US-004 : Reset de mot de passe

**Titre :** L'utilisateur peut réinitialiser son mdp

**Description :**
- Page `/forgot-password`
- Entre email
- Générer token reset (UUID aléatoire, exp 24h)
- Stocker en DB avec email + expiration
- (OPTIONNEL : envoyer email, pour v1 juste afficher lien)
- Utilisateur clique lien `/reset-password?token=XXX`
- Peut entrer nouveau mdp
- Token consommé (supprimé de DB)
- Audit log : `password_reset_requested`, `password_reset_completed`

**Priorité :** Haute

**Semaine :** S4

**Tests :**
- ✅ Token invalide → erreur
- ✅ Token expiré → erreur
- ✅ Reset valide → mdp changé
- ✅ Token peut être utilisé qu'une fois

---

### US-005 : Activer 2FA TOTP

**Titre :** L'utilisateur peut activer l'authentification à deux facteurs

**Description :**
- Accès `/settings/2fa`
- Générer secret TOTP (base32)
- Afficher QR code + secret brut
- Utilisateur scanne avec Google Authenticator
- Utilisateur entre 6 chiffres pour confirmer
- Vérifier le code
- Générer 10 backup codes (format : XXXX-XXXX-XXXX)
- Afficher codes pour téléchargement/impression
- Audit log : `2fa_enabled`

**Priorité :** Critique

**Semaine :** S4

**Tests :**
- ✅ Secret TOTP généré + QR valide
- ✅ Code TOTP correct → 2FA activé
- ✅ Code TOTP faux → refusé
- ✅ Backup codes générés (10)
- ✅ Utilisateur peut télécharger codes

---

### US-006 : Login avec 2FA

**Titre :** Le login demande le code TOTP si activé

**Description :**
- Après US-002 (login classique)
- Si user a 2FA : afficher page "Entrez code TOTP"
- Utilisateur entre 6 chiffres
- Vérifier : code valide + timestamp pas expiré (±30s)
- Si valide : créer session complète
- Si 3 tentatives échouées : bloquer 15 min
- Audit log : `2fa_verified` ou `2fa_failed`

**Priorité :** Critique

**Semaine :** S4

**Tests :**
- ✅ 2FA code correct → login réussi
- ✅ 2FA code faux → erreur
- ✅ Code expiré (après 30s) → erreur
- ✅ 3 tentatives échouées → bloquer 15 min
- ✅ Backup code accepté (et consommé)

---

### US-007 : Utiliser backup codes

**Titre :** L'utilisateur peut se connecter avec un backup code

**Description :**
- Pendant 2FA, proposer "Ou entrez un backup code"
- Utilisateur entre un code (format XXXX-XXXX-XXXX)
- Vérifier : code existe + pas encore consommé
- Marquer code comme consommé (pour pas réutiliser)
- Login réussi
- Audit log : `backup_code_used`

**Priorité :** Haute

**Semaine :** S4

**Tests :**
- ✅ Backup code valide → login réussi
- ✅ Code déjà consommé → refusé
- ✅ Code invalide → erreur

---

## BLOC 2 : TICKETS ET PROJETS (S5)

### US-008 : Créer un ticket

**Titre :** L'utilisateur peut créer un ticket

**Description :**
- Accès `/tickets/create`
- Formulaire : titre (50-200 chars) + description (text) + priorité (low/medium/high/critical) + projet (dropdown)
- Valider entrées (longueur, pas XSS)
- Créer ticket en DB
- Ticket.created_by = user courant
- Ticket.status = "open"
- Redirection vers ticket détail
- Audit log : `ticket_created`

**Priorité :** Critique

**Semaine :** S5

**Tests :**
- ✅ Création valide → ticket créé
- ✅ Titre trop long → erreur
- ✅ XSS dans description → échappé
- ✅ Utilisateur peut voir son ticket après création

---

### US-009 : Lister les tickets

**Titre :** L'utilisateur voir ses tickets

**Description :**
- Accès `/tickets`
- Afficher tableau avec : ID, Titre, Statut, Priorité, Créé le
- Filter par statut (dropdown : tous, open, in progress, closed)
- Trier par date création ou priorité
- Pagination si > 50 tickets
- Audit log : `tickets_viewed`

**Priorité :** Critique

**Semaine :** S5

**Tests :**
- ✅ User voit ses tickets (pas ceux d'autres users)
- ✅ Manager voit tickets de son équipe
- ✅ Admin voit tous les tickets
- ✅ Filter + sort fonctionnent

---

### US-010 : Voir détail d'un ticket

**Titre :** L'utilisateur peut consulter un ticket

**Description :**
- Accès `/tickets/{ticket_id}`
- Afficher : titre, description, statut, priorité, créé_par, assigné_à, date création, date modif
- Si autorisé (owner / manager / admin) : bouton "Modifier" ou "Assigner"
- Si pas autorisé : affichage read-only
- Audit log : `ticket_viewed`

**Priorité :** Critique

**Semaine :** S5

**Tests :**
- ✅ Utilisateur voit son ticket
- ✅ Utilisateur ne voit pas ticket d'autres users (HTTP 403)
- ✅ Admin voit tous les tickets
- ✅ Audit log enregistre l'accès

---

### US-011 : Modifier un ticket

**Titre :** L'utilisateur peut modifier un ticket

**Description :**
- Accès `/tickets/{ticket_id}/edit`
- Modifier : titre, description, statut, priorité
- Vérifier autorisation : user = owner OU manager/admin
- Valider entrées (pas XSS)
- Sauvegarder en DB
- Audit log : `ticket_modified` (avant/après)
- Redirection vers détail

**Priorité :** Haute

**Semaine :** S5

**Tests :**
- ✅ Owner peut modifier son ticket
- ✅ User ne peut pas modifier ticket d'autres
- ✅ Manager peut modifier tickets de son équipe
- ✅ Admin peut modifier tout
- ✅ Audit log trace modification (champs modifiés)

---

### US-012 : Supprimer un ticket

**Titre :** L'utilisateur peut supprimer un ticket

**Description :**
- Bouton "Supprimer" sur détail ticket
- Confirmation avant suppression
- Vérifier autorisation : user = owner OU admin
- Soft-delete (marquer deleted_at, pas vraiment supprimer)
- Audit log : `ticket_deleted`

**Priorité :** Moyenne

**Semaine :** S5

**Tests :**
- ✅ Owner peut supprimer son ticket
- ✅ User ne peut pas supprimer ticket d'autres
- ✅ Admin peut supprimer tout
- ✅ Soft-delete : ticket caché mais traçable en audit

---

### US-013 : Créer un projet

**Titre :** L'utilisateur peut créer un projet

**Description :**
- Accès `/projects/create`
- Formulaire : nom (50-100 chars) + description (text)
- Créer projet en DB
- Project.created_by = user courant
- Project.members = [user courant] (creator = owner)
- Redirection vers détail projet
- Audit log : `project_created`

**Priorité :** Haute

**Semaine :** S5

**Tests :**
- ✅ Création valide → projet créé
- ✅ User = owner du projet
- ✅ User peut voir son projet

---

### US-014 : Ajouter utilisateurs à un projet

**Titre :** Le project owner peut ajouter des membres

**Description :**
- Accès `/projects/{project_id}/members`
- Dropdown : sélectionner user
- Sélectionner rôle : viewer / editor / manager
- Ajouter en DB (project_members table)
- Audit log : `project_member_added`

**Priorité :** Haute

**Semaine :** S5

**Tests :**
- ✅ Owner peut ajouter members
- ✅ Non-owner ne peut pas (HTTP 403)
- ✅ Member peut accéder tickets du projet (selon rôle)

---

## BLOC 3 : RÔLES ET ACCÈS (S6)

### US-015 : Rôles système (user, manager, admin)

**Titre :** Les rôles contrôlent l'accès

**Description :**
- **User** : peut voir ses propres tickets, créer tickets
- **Manager** : peut voir tickets de son équipe, assigner, créer projets
- **Admin** : accès complet, gestion utilisateurs, audit logs

**Priorité :** Critique

**Semaine :** S6

**Tests :**
- ✅ User ne voit que ses tickets
- ✅ Manager voit équipe
- ✅ Admin voit tout

---

### US-016 : Changer le rôle d'un utilisateur

**Titre :** Admin peut changer le rôle d'un utilisateur

**Description :**
- Accès `/admin/users`
- Afficher liste users avec rôles
- Dropdown pour changer rôle
- Sauvegarder en DB
- Audit log : `user_role_changed` (from=X, to=Y, changed_by=admin)

**Priorité :** Haute

**Semaine :** S6

**Tests :**
- ✅ Seul admin peut changer rôles
- ✅ User ne peut pas changer son rôle
- ✅ User ne peut pas devenir admin (vérification backend)

---

## BLOC 4 : SÉCURITÉ (S7-S12)

### US-017 : Protection CSRF

**Titre :** Tous les formulaires ont un token CSRF

**Description :**
- Générer CSRF token unique par session
- Injecter dans chaque formulaire (`<input type="hidden" name="csrfmiddlewaretoken">`)
- Vérifier token avant traiter POST/PUT/DELETE
- Si token invalide : 403 Forbidden
- Django middleware CSRF activé par défaut

**Priorité :** Critique

**Semaine :** S7

**Tests :**
- ✅ Formulaire valide avec token → accepté
- ✅ Formulaire sans token → 403
- ✅ Token invalide → 403
- ✅ Token réutilisable (une fois par request)

---

### US-018 : Protection XSS

**Titre :** Toutes les données affichées sont échappées

**Description :**
- Django templates auto-escape par défaut (`{{ variable }}`)
- Pas d'utilisation `|safe` sans vérification
- Test : insérer `<script>alert('XSS')</script>` dans description ticket
- Vérifier que script n'exécute pas (échappé en HTML)

**Priorité :** Critique

**Semaine :** S7

**Tests :**
- ✅ `<script>` affiché comme texte (échappé)
- ✅ `<img src=x onerror=alert()>` ne s'exécute pas
- ✅ Toutes les données utilisateur échappées

---

### US-019 : En-têtes sécurité HTTP

**Titre :** L'app ajoute les en-têtes sécurité recommandés

**Description :**
- `X-Content-Type-Options: nosniff` (pas de MIME sniffing)
- `X-Frame-Options: DENY` (pas d'iframe)
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains` (HSTS)
- `Content-Security-Policy: default-src 'self'; script-src 'self'` (CSP)
- Configurer dans Django (settings.py ou middleware)

**Priorité :** Critique

**Semaine :** S7

**Tests :**
- ✅ Headers présents dans réponses HTTP
- ✅ Vérifier avec curl : `curl -I http://localhost:8000`

---

### US-020 : Audit logs

**Titre :** Tous les événements sensibles sont loggés

**Description :**
- Créer table `audit_logs` avec : timestamp, user_id, action, resource_type, resource_id, details, ip_address
- Logger : login, logout, 2fa_verified, ticket_created, ticket_modified, user_role_changed, access_denied, etc.
- Logs immuables (jamais modifiés après création)
- Admin peut voir logs : `/admin/audit-logs`

**Priorité :** Critique

**Semaine :** S8

**Tests :**
- ✅ Chaque action sensible → log créé
- ✅ Log contient user, timestamp, action, détails
- ✅ Logs lisibles en admin

---

### US-021 : Scan SAST (Bandit)

**Titre :** Le code est scanné pour vulnérabilités

**Description :**
- Intégrer Bandit dans CI/CD
- Exécuter à chaque commit : `bandit -r src/`
- Générer rapport JSON
- Bloquer si vulnérabilité High (optionnel pour S1, stricte pour S12)

**Priorité :** Haute

**Semaine :** S8

**Tests :**
- ✅ Bandit détecte hardcoded secrets
- ✅ Bandit détecte SQL injection potentielle
- ✅ Rapport généré automatiquement

---

### US-022 : Scan DAST (OWASP ZAP)

**Titre :** L'app est testée dynamiquement avec ZAP

**Description :**
- Lancer instance de l'app en staging
- Exécuter ZAP : `zaproxy -cmd -quickurl http://localhost:8000`
- Générer rapport HTML
- Classifier vulnérabilités : Critical, High, Medium, Low, Info
- Documenter chaque finding + fix proposé

**Priorité :** Haute

**Semaine :** S8

**Tests :**
- ✅ ZAP scan complété
- ✅ Rapport généré (HTML)
- ✅ Vulnerabilités classées

---

## BLOC 5 : DEVOPS (S10)

### US-023 : CI/CD pipeline

**Titre :** Pipeline automatisé pour tester et déployer

**Description :**
- GitHub Actions workflow
- Déclenché à chaque push sur `main` et `develop`
- Étapes :
  1. Checkout code
  2. Setup Python 3.11
  3. Install dépendances
  4. Lint (flake8)
  5. Tests (pytest)
  6. SAST (Bandit)
  7. Safety check
  8. Build Docker image
  9. Deploy en staging (si main)
- Rapport généré après chaque run

**Priorité :** Haute

**Semaine :** S10

**Tests :**
- ✅ Pipeline exécuté à chaque push
- ✅ Tous les checks passent
- ✅ Build Docker réussi

---

### US-024 : Scan conteneur (Trivy)

**Titre :** Les images Docker sont scannées pour vulnérabilités

**Description :**
- Intégrer Trivy dans CI
- Exécuter avant déploiement
- Rapport : CVE détectées dans dépendances
- Bloquer si vulnerability Critical (optionnel)

**Priorité :** Moyenne

**Semaine :** S10

**Tests :**
- ✅ Trivy scan conteneur
- ✅ Rapport généré

---

### US-025 : Scan secrets (Gitleaks)

**Titre :** Détecter les secrets leakés en code

**Description :**
- Intégrer Gitleaks dans CI
- Détecte : API keys, passwords, tokens en code
- Rapport + blocage si secret trouvé

**Priorité :** Critique

**Semaine :** S10

**Tests :**
- ✅ Gitleaks détecte secrets
- ✅ Blocage si secret trouvé

---

## BLOC 6 : FONCTIONS AVANCÉES (S9)

### US-026 : Upload sécurisé de fichiers

**Titre :** Utilisateurs peuvent attacher des fichiers aux tickets

**Description :**
- Endpoint `/tickets/{id}/upload`
- Valider : extension fichier (whitelist : pdf, doc, docx, jpg, png, csv)
- Valider : taille max (10 MB)
- Renommer fichier (UUID + ext d'origine)
- Stocker en `/uploads/{uuid}`
- Audit log : `file_uploaded`
- Endpoint `/files/{uuid}` pour download (avec vérification autorisation)

**Priorité :** Moyenne

**Semaine :** S9

**Tests :**
- ✅ Upload fichier valide → accepté
- ✅ Upload .exe → rejeté
- ✅ Upload > 10MB → rejeté
- ✅ Utilisateur peut récupérer ses fichiers
- ✅ Utilisateur ne peut pas accéder fichiers d'autres

---

## BLOC 7 : RAPPORT (S13)

### US-027 : Rapport d'analyse de sécurité

**Titre :** Document d'analyse sécurité livré

**Description :**
- Rapport PDF avec sections :
  1. Périmètre + objectifs
  2. Menaces identifiées (STRIDE)
  3. Implémentation des protections
  4. Résultats tests (SAST, DAST, tests unitaires)
  5. Mapping OWASP Top 10 (A01 à A10)
  6. Mapping OWASP ASVS niveau 1 + 2
  7. Vulnérabilités résiduelles + plans futurs
  8. Conclusion

**Priorité :** Critique

**Semaine :** S13

---

## Résumé par semaine

| Semaine | US | Count | Focus |
|---------|----|----|--------|
| S1-S2 | Setup | — | Infra, repo, CI/CD |
| S3 | US-001, 002, 003 | 3 | Auth de base |
| S4 | US-004, 005, 006, 007 | 4 | 2FA + reset |
| S5 | US-008 à 014 | 7 | Tickets, projets |
| S6 | US-015, 016 | 2 | RBAC |
| S7 | US-017, 018, 019 | 3 | Hardening web |
| S8 | US-020, 021, 022 | 3 | Audit, scans |
| S9 | US-026 | 1 | Upload sécurisé |
| S10 | US-023, 024, 025 | 3 | CI/CD avancée |
| S11-S12 | Tests + fixes | — | Régression, corrections |
| S13 | US-027 | 1 | Rapport final |
| S14 | Soutenance | — | Présentation |

**Total : ~27 user stories**
