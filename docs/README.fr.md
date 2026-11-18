# Présentation en français — TP AWS CloudTrail

## Objectif pédagogique

Reproduire une chaîne d'investigation cloud : préparer des ressources S3/IAM émulées, collecter des journaux **synthétiques** au format CloudTrail, détecter des anomalies avec Python et expliquer une compromission avec des preuves traçables.

**Contexte :** une entreprise fictive perd un bucket de sauvegarde et subit une interruption de la journalisation. L'analyste recherche l'identité, les actions, la période, l'IP d'origine, l'impact et les actions de réponse.

## Réalisations

1. **Environnement** : Docker Compose, conteneur d'analyse avec AWS CLI/Python/jq, LocalStack Community 4.14.
2. **Ressources** : quatre buckets (`corp-app-data`, `corp-backups-prod`, `corp-finance-secrets`, `corp-cloudtrail-logs-synthetic`) et quatre identités IAM (`alice`, `bob`, `carol`, `svc-backup`).
3. **Simulation locale** : attribution d'AdministratorAccess à Bob, création d'une clé pour `svc-backup`, suppression puis restauration du bucket de sauvegarde.
4. **Journalisation** : génération reproductible de **265 événements synthétiques**, organisés en **114 fichiers `.json.gz`** et transférés dans S3 local.
5. **Détection** : neuf règles (R01–R09) ; **20 alertes** avec le seuil de silence de 30 minutes.
6. **Investigation** : six scénarios liés, chronologie UTC, `eventID`, IP d'origine, faux positifs, trou de journalisation de 71 minutes.
7. **Documentation** : rapport Markdown/JSON/CSV, captures d'écran et recommandations.

## Résultats observés

| Gravité | Nombre |
| --- | ---: |
| CRITICAL | 9 |
| HIGH | 2 |
| MEDIUM | 2 |
| LOW | 6 |
| INFO | 1 |

Un seuil de silence de **5 min** génère 126 alertes MEDIUM (beaucoup de bruit). À **120 min**, le trou de 71 min n'est plus détecté par R08. Le seuil de **30 min** a été conservé pour ce dataset ; il ne constitue pas un réglage universel.

## Ce qui a vraiment été réalisé

Les appels S3/IAM au niveau LocalStack ont réellement modifié **l'émulateur local**, mais n'ont pas été effectués dans un compte AWS public. Les événements CloudTrail investigués proviennent de `generate_events.py` et **ne sont pas des journaux AWS réels**. Les événements synthétiques attribués à Bob ne prouvent pas qu'un test IAM réel a été conduit avec des identifiants de Bob.

## Pour commencer

Voir le guide [SETUP.md](SETUP.md), puis [DETECTION_RULES.md](DETECTION_RULES.md), [INCIDENT_WALKTHROUGH.md](INCIDENT_WALKTHROUGH.md) et [TROUBLESHOOTING.md](TROUBLESHOOTING.md).
