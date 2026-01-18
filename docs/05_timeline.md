# TIMELINE — SecureTrack (14 semaines)

## Semaines 1-2 : Cadrage + Setup

- S1 : Périmètre, DFD, menaces, stack, backlog
- S2 : Repo Git, Docker Compose, CI/CD basique, SAST setup

**Jalon fin S2 :** ✅ Environnement prêt, pipeline CI "vert"

---

## Semaines 3-4 : Authentification

- S3 : Auth de base (signup/login/logout) + Argon2id
- S4 : 2FA TOTP + codes de secours + rate limiting

**Jalon fin S4 :** ✅ Auth complète + 2FA démontrables

---

## Semaines 5-6 : Métier + RBAC

- S5 : Modèles Ticket/Projet, CRUD basique, UI simple
- S6 : RBAC (user/manager/admin), contrôles d'accès, tests autorisation

**Jalon fin S6 :** ✅ Tickets + RBAC fonctionnels, 0 privilege escalation

---

## Semaines 7-8 : Hardening + DAST v1

- S7 : CSRF tokens, XSS protection, en-têtes sécurité (CSP, HSTS, etc.)
- S8 : Audit logs, première scan ZAP, plan remédiation

**Jalon fin S8 :** ✅ ZAP v1 terminé, vulnerabilités classées par priorité

---

## Semaines 9-10 : DevSecOps avancée

- S9 : Upload sécurisé, rotation session, CSP stricte
- S10 : ZAP automatisé en CI, Trivy (scan conteneur), Gitleaks (secrets), déploiement staging

**Jalon fin S10 :** ✅ Pipeline "vert" avec tous les scans, instance staging live

---

## Semaines 11-12 : Revue + corrections

- S11 : Observabilité (logs structurés, alertes), backup/restore testés
- S12 : Revue interne (pentest + code review), corrections, tests régression

**Jalon fin S12 :** ✅ 0 vulnérabilité High/Critical, 0 dépendances non-patchées

---

## Semaines 13-14 : Documentation + Soutenance

- S13 : Rapport final (SAST/DAST, DFD v3, STRIDE v3, mapping OWASP Top 10 + ASVS)
- S14 : Polissage, répétition démo, soutenance

**Livrable final :** ✅ Code complet + rapport PDF + vidéo démo

---

## Jalons critiques de communication avec le prof

| Date | Jalon | Livrables |
|------|-------|-----------|
| Fin S1 | Cadrage validé | Périmètre, DFD, menaces, stack |
| Fin S2 | Repo + CI OK | Repo GitHub, pipeline vert, Dockerfile |
| Fin S4 | Auth démontrée | Démo signup/login/2FA en live |
| Fin S8 | ZAP v1 + plan | Rapport ZAP, liste fixes, priorités |
| Fin S12 | Release candidate | 0 High/Critical, tests verts |
| S14 | Soutenance | Présentation 15-20 min + Q&A |

