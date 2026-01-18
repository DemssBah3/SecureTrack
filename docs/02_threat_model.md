# MODÈLE DE MENACES — STRIDE v1

## Vue d'ensemble

On utilise la méthode **STRIDE** pour identifier les menaces :
- **S**poofing : Usurpation d'identité
- **T**ampering : Modification non autorisée
- **R**epudiation : Nier une action
- **I**nformation Disclosure : Fuite de données sensibles
- **D**enial of Service : Indisponibilité du service
- **E**levation of Privilege : Escalade de droits

---

## Tableau des menaces

| # | Actif ciblé | Type STRIDE | Scénario d'attaque | Impact | Probabilité | Mitigation | Priorité |
|----|-------------|-------------|-------------------|--------|------------|-----------|----------|
| 1 | Mots de passe | **S**poofing | Attaquant brute-force le login (100000 tentatives) | Accès compte utilisateur | Moyenne | Rate limiting (5 tentatives / 15 min) + Captcha | **HAUTE** |
| 2 | Sessions utilisateur | **T**ampering | Attaquant modifie le cookie de session pour prendre l'ID d'un admin | Accès admin | Basse (cookies signés) | Cookies sécurisés (HttpOnly, Secure, SameSite) + chiffrement | **CRITIQUE** |
| 3 | Données tickets | **I**nformation Disclosure | Un utilisateur voit les tickets d'un autre utilisateur via paramètre ?ticket_id=2 | Fuite données sensibles | Moyenne | RBAC strict + tests d'autorisation à chaque requête | **HAUTE** |
| 4 | API utilisateur | **E**levation of Privilege | Un utilisateur normal modifie son rôle en "admin" via requête PUT | Accès admin non autorisé | Basse (si tests bons) | Vérification du rôle en backend (jamais côté client) + audit logs | **CRITIQUE** |
| 5 | Application | **D**enial of Service | Attaquant inonde l'app de 10000 requêtes/sec | App indisponible | Basse | Rate limiting global + monitoring des requêtes | **MOYENNE** |
| 6 | Audit logs | **R**epudiation | Utilisateur agit, puis nie (logs supprimés ou falsifiés) | Pas de traçabilité | Moyenne | Logs immuables + sauvegarde séparée + signature | **MOYENNE** |
| 7 | Données en transit | **T**ampering | Attaquant intercepte requête HTTP et modifie le mot de passe | Compte compromis | Basse (avec HTTPS) | HTTPS obligatoire + HSTS | **HAUTE** |
| 8 | Mots de passe stockés | **I**nformation Disclosure | Attaquant accède à la DB et récupère les mots de passe | Tous les comptes compromis | Moyenne | Hachage Argon2id (GPU-resistant) + salt unique | **CRITIQUE** |
| 9 | Upload fichiers | **T**ampering | Attaquant upload un fichier .exe malveillant | Exécution de code | Moyenne | Validation stricte (types/tailles), antivirus optionnel, stockage isolé | **HAUTE** |
| 10 | XSS dans tickets | **T**ampering | Attaquant ajoute `<script>alert('XSS')</script>` dans une description | Vol de session d'autres users | Moyenne | Échappement des données en sortie + CSP stricte | **HAUTE** |
| 11 | CSRF | **T**ampering | Attaquant force admin à supprimer des tickets via formulaire caché | Actions non consentis | Moyenne | CSRF token sur tous formulaires | **HAUTE** |
| 12 | Secrets en dur | **I**nformation Disclosure | Clés API/JWT hardcodées dans le code | Accès non autorisé | Haute | Fichier .env + variables d'environnement | **HAUTE** |
| 13 | 2FA désactivé | **S**poofing | Attaquant force l'utilisateur à désactiver 2FA | Accès compte | Basse (user consent) | Confirmation email + audit logs | **MOYENNE** |

---

## Priorité de mitigation

**CRITIQUE (implémenter Semaines 1-4) :**
- Hachage Argon2id
- Cookies sécurisés
- RBAC strict + tests
- Vérification rôle en backend

**HAUTE (implémenter Semaines 3-8) :**
- Rate limiting
- HTTPS + HSTS
- XSS protection + CSP
- CSRF tokens
- Upload sécurisé

**MOYENNE (implémenter Semaines 9-12) :**
- Rate limiting global
- Audit logs immuables
- Secrets en variables d'env
- Confirmation actions sensibles
