# TP CloudTrail — Investigation et détection cloud

Ce dépôt documente un TP d'analyse de sécurité AWS réalisé avec **LocalStack**, **AWS CLI**, **Python** et **jq**.

> **Distinction fondamentale :** S3, IAM et STS sont émulés localement. Les **265 journaux au format CloudTrail sont synthétiques** et ne proviennent pas d'un service CloudTrail réel.

## Objectifs pédagogiques

1. Initialiser un environnement cloud émulé et étudier une politique IAM excessivement permissive.
2. Manipuler des buckets S3 et quatre identités : Alice, Bob, Carol et `svc-backup`.
3. Simuler localement une élévation de privilèges, une création de clé et une suppression de sauvegarde.
4. Générer 265 événements CloudTrail-like en 114 fichiers compressés.
5. Centraliser ces fichiers dans S3 local puis les analyser.
6. Appliquer neuf règles R01 à R09 ; expliquer les faux positifs et les seuils de détection.
7. Reconstituer un incident en six scénarios, avec `eventTime`, `eventID`, identités et adresses IP.
8. Proposer une réponse à incident et documenter les preuves et limites.

## Résultats

**265 événements**, **114 fichiers .json.gz**, **20 alertes** au seuil de 30 min : 9 CRITICAL, 2 HIGH, 2 MEDIUM, 6 LOW, 1 INFO.

L'investigation synthétique décrit un accès suspect au compte Bob sans MFA, des requêtes IAM/S3 refusées, une élévation de privilèges, la création d'une clé pour `svc-backup`, la suppression du bucket `corp-backups-prod` et un arrêt de journalisation d'environ 71 minutes.

## Documentation

- [Architecture](ARCHITECTURE.md)
- [Installation et exécution](SETUP.md)
- [Règles de détection](DETECTION_RULES.md)
- [Investigation détaillée](INCIDENT_WALKTHROUGH.md)
- [Résultats](RESULTS.md)
- [Dépannage](TROUBLESHOOTING.md)
- [Attribution des sources](SOURCE_ATTRIBUTION.md)

## Ce que l'étudiant a réellement fait

Configuration et dépannage Docker, validation des services émulés, commandes S3/IAM, simulation d'activité, collecte, analyse JSON, réglage des seuils, chronologie avec preuves, recommandations et compte rendu.

Le cours original est attribué à **Pr. JAADOUNI Hatim (EMSI)**. Les scripts de départ et données synthétiques provenaient du support pédagogique : leur origine doit être reconnue.
