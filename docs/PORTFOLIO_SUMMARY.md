# Portfolio description

## Short English summary

**Cloud Security / DFIR lab — AWS CloudTrail-format Detection & Incident Investigation:** Reproduced an educational local S3/IAM environment using Docker and LocalStack. Generated and ingested 265 deterministic **synthetic** CloudTrail-style events in 114 compressed S3 objects; analyzed them using Python detection rules R01–R09 and reconstructed a six-stage IAM/S3 attack narrative. Practiced evidence correlation, false-positive tuning (5/30/120-minute log-gap thresholds) and remediation planning. **No real AWS account or native CloudTrail service was used.**

## Présentation courte en français

**Laboratoire Cloud Security / DFIR — Détection et investigation sur journaux de type AWS CloudTrail :** réalisation d'un environnement S3/IAM émulé avec Docker et LocalStack, génération de 265 événements **synthétiques** répartis dans 114 fichiers compressés, application de neuf règles de détection Python et investigation d'une chaîne de six scénarios cloud. Analyse des preuves `eventID`, réglage des seuils et propositions de remédiation. Aucun compte AWS réel ni service CloudTrail actif n'a été utilisé.

## Suggested skills / topics

Docker, Docker Compose, AWS CLI, LocalStack, AWS S3/IAM/STS concepts, CloudTrail JSON format, Python, jq, detection engineering, incident timeline, IAM privilege escalation analysis, backup security, logging defense impairment, MITRE ATT&CK.
