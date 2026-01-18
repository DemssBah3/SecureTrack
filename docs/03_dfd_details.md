# DATA FLOW DIAGRAM — SecureTrack v1

## Flux 1 : Inscription utilisateur

Utilisateur ↓ (POST /register avec email + mdp) Nginx (reverse proxy, HTTPS) ↓ (demande) Django App ├─ Validation email (regex + unicité) ├─ Validation mdp (force, longueur) ├─ Hachage Argon2id └─ Validation CSRF token ↓ (INSERT user) PostgreSQL ├─ Stockage : email, hash_mdp, created_at ├─ Génération clé secrète TOTP (optionnel) └─ Création audit log ↓ (user_created event) Audit logs table


**Points sensibles :**
- 🔴 Mots de passe JAMAIS en clair
- 🔴 HTTPS obligatoire (pas HTTP)
- 🔴 CSRF token nécessaire
- 🟢 Argon2id GPU-resistant
- 🟢 Audit log créé

---

## Flux 2 : Login utilisateur

Utilisateur ↓ (POST /login avec email + mdp) Nginx (HTTPS) ↓ Django App ├─ Rate limiting check (max 5 tentatives / 15 min) ├─ Recherche utilisateur par email ├─ Vérification hash Argon2id (mdp vs stored hash) ├─ Génération session token ├─ Stockage session (DB ou cache) └─ Audit log : login_success ↓ (SET-COOKIE session_id) Session store (DB)

Si 2FA activé : ├─ Affiche écran "Entrez code TOTP" ├─ Vérification code TOTP (6 chiffres + timestamp) └─ Audit log : 2fa_verified


**Points sensibles :**
- 🔴 Rate limiting (anti-brute-force)
- 🔴 Comparaison hash sécurisée (pas de temps variable)
- 🟢 Session token aléatoire
- 🟢 2FA verification

---

## Flux 3 : Accès aux tickets (avec RBAC)

Utilisateur authentifié ↓ (GET /tickets) Nginx (HTTPS + session_id cookie) ↓ Django App ├─ Vérification session (user_id) ├─ Requête : SELECT tickets WHERE ... │ ├─ Si user = owner : voir tous ses tickets │ ├─ Si user = manager : voir tickets de son équipe │ └─ Si user = admin : voir tous les tickets │ (RBAC check) └─ Audit log : tickets_viewed ↓ (SELECT from db) PostgreSQL └─ Retour tickets + métadonnées ↓ (JSON response) Nginx → Utilisateur (HTML/JSON)


**Points sensibles :**
- 🔴 RBAC vérifié en backend (jamais côté client)
- 🔴 Pas de requête par ID directe (toujours filtrer par user)
- 🟢 Audit log des accès

---

## Flux 4 : Modification des rôles (Admin only)

Admin ↓ (POST /users/{user_id}/role avec new_role=admin) Nginx (HTTPS) ↓ Django App ├─ Vérification : current_user.role == 'admin' ? ├─ Si OUI : mise à jour du rôle ├─ Audit log : role_changed (from=user, to=admin, changed_by=admin_id) └─ Si NON : 403 Forbidden + audit log : unauthorized_role_change_attempt ↓ (UPDATE users SET role) PostgreSQL └─ Sauvegarde + audit trace


**Points sensibles :**
- 🔴 Vérification rôle STRICT en backend
- 🔴 Jamais faire confiance aux données client
- 🟢 Audit log de chaque modification sensible

---

## Stockage des données sensibles

| Donnée | Stockage | Protection |
|--------|----------|-----------|
| Mots de passe | PostgreSQL (hash Argon2id) | ✅ Hachage irreversible |
| Clés TOTP secrètes | PostgreSQL (encrypted) | ✅ Chiffrement à repos |
| Sessions | Session table DB | ✅ HttpOnly + Secure cookies |
| Audit logs | Audit logs table | ✅ Immutable + backup séparé |
| JWT secrets (si utilisés) | .env (variables) | ✅ Jamais en dur |
| Fichiers uploadés | Stockage système (validé) | ✅ Scan antivirus optionnel |