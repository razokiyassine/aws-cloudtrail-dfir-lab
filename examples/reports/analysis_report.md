# Rapport d'analyse automatique de journaux de type CloudTrail

> **Avertissement** : si l'entrée est `data/s3_layout` ou `data/dataset_*.json`, ces événements sont **synthétiques** (générés par `generate_events.py`). Ils ne proviennent pas d'un vrai CloudTrail.

## 1. Périmètre

- Fichiers lus : 114 (illisibles : 0)
- Événements uniques analysés : **265**
- Période couverte : 2026-10-28T06:03:00Z -> 2026-10-29T05:51:17Z
- Plages IP de confiance : `198.51.100.0/24,10.0.0.0/8` | seuil de silence : 30 min

## 2. Synthèse des alertes

| Sévérité | Nombre |
|---|---|
| CRITICAL | 9 |
| HIGH | 2 |
| MEDIUM | 2 |
| LOW | 6 |
| INFO | 1 |

| Règle | Titre | Alertes | MITRE ATT&CK |
|---|---|---|---|
| R01 | Connexion console sans MFA | 1 | T1078.004 Valid Accounts: Cloud Accounts |
| R02 | Attribution de privilèges administrateur | 1 | T1098.003 Account Manipulation: Additional Cloud Roles |
| R03 | Clé d'accès non autorisée / usage suspect | 3 | T1098.001 Account Manipulation: Additional Cloud Credentials |
| R04 | Suppression de bucket S3 | 2 | T1485 Data Destruction |
| R05 | Altération de la journalisation CloudTrail | 2 | T1562.008 Impair Defenses: Disable or Modify Cloud Logs |
| R06 | Accès refusé(s) à des ressources | 7 | T1580 Cloud Infrastructure Discovery / T1087.004 Cloud Account Discovery |
| R07 | Échecs de connexion console répétés | 1 | T1110 Brute Force |
| R08 | Trou de journalisation | 1 | T1562.008 Impair Defenses: Disable or Modify Cloud Logs |
| R09 | Activité depuis une IP hors périmètre | 2 | T1078.004 Valid Accounts: Cloud Accounts |

## 3. Alertes de sévérité MEDIUM ou plus

### [CRITICAL] R07 - Échecs de connexion console répétés
- **Quand** : 2026-10-29T02:11:07Z | **Qui** : `bob` | **IP** : `203.0.113.66` | **Événement** : `ConsoleLogin`
- **Détail** : 3 échecs de connexion pour bob depuis 203.0.113.66 puis SUCCÈS à 2026-10-29T02:14:30Z (compromission probable)
- **eventID(s)** : 4970ed9a-09ce-4cfb-a339-ba1925637cc3, b49e04cc-c243-49e7-a387-eaf6d4c3a832, 41843b03-04dd-4054-9448-23f7e7e646c7, 871c0884-9bdf-40f2-ba2c-0f19f0b2a5d1

### [CRITICAL] R01 - Connexion console sans MFA
- **Quand** : 2026-10-29T02:14:30Z | **Qui** : `bob` | **IP** : `203.0.113.66` | **Événement** : `ConsoleLogin`
- **Détail** : Connexion réussie de bob sans MFA depuis 203.0.113.66
- **eventID(s)** : 871c0884-9bdf-40f2-ba2c-0f19f0b2a5d1

### [CRITICAL] R06 - Accès refusé(s) à des ressources
- **Quand** : 2026-10-29T02:16:02Z | **Qui** : `bob` | **IP** : `203.0.113.66` | **Événement** : `ListUsers`
- **Détail** : RAFALE : 4 refus en <10 min pour bob (GetBucketPolicy, GetObject, ListRoles, ListUsers) depuis 203.0.113.66
- **eventID(s)** : b7f28572-3def-4849-9336-4f7e83efa9f3, 40ef3935-5f90-4ed6-bb25-664d630aa767, 10275b53-2285-42ef-8fbe-4fe92ea9c542, 0c3ce284-c7e5-4bbb-9cb5-1c535b62a8df

### [CRITICAL] R02 - Attribution de privilèges administrateur
- **Quand** : 2026-10-29T02:21:40Z | **Qui** : `bob` | **IP** : `203.0.113.66` | **Événement** : `AttachUserPolicy`
- **Détail** : bob -> AttachUserPolicy arn:aws:iam::aws:policy/AdministratorAccess sur 'bob' (attribution réussie) depuis 203.0.113.66
- **eventID(s)** : 6cac028c-ba22-4065-9526-0718cd180a82

### [CRITICAL] R03 - Clé d'accès non autorisée / usage suspect
- **Quand** : 2026-10-29T02:23:15Z | **Qui** : `bob` | **IP** : `203.0.113.66` | **Événement** : `CreateAccessKey`
- **Détail** : bob a créé une clé d'accès pour un AUTRE utilisateur 'svc-backup' (clé AKIALABROGUE00000001) depuis 203.0.113.66
- **eventID(s)** : e95f176c-deba-4186-ba10-82170ad7c9a2

### [CRITICAL] R04 - Suppression de bucket S3
- **Quand** : 2026-10-29T02:33:05Z | **Qui** : `bob` | **IP** : `203.0.113.66` | **Événement** : `DeleteBucket`
- **Détail** : bob a supprimé le bucket 'corp-backups-prod' depuis 203.0.113.66
- **eventID(s)** : 1e2595b8-8fc9-486b-a9dd-ebf563119aca

### [CRITICAL] R05 - Altération de la journalisation CloudTrail
- **Quand** : 2026-10-29T02:39:20Z | **Qui** : `bob` | **IP** : `203.0.113.66` | **Événement** : `DeleteTrail`
- **Détail** : bob : DeleteTrail sur arn:aws:cloudtrail:eu-west-3:000000000000:trail/corp-trail -> tentative REFUSÉE (AccessDeniedException) depuis 203.0.113.66
- **eventID(s)** : 51d08109-fc90-4838-9874-1408f7b217c7

### [CRITICAL] R05 - Altération de la journalisation CloudTrail
- **Quand** : 2026-10-29T02:41:03Z | **Qui** : `bob` | **IP** : `203.0.113.66` | **Événement** : `StopLogging`
- **Détail** : bob : StopLogging sur arn:aws:cloudtrail:eu-west-3:000000000000:trail/corp-trail -> tentative RÉUSSIE depuis 203.0.113.66
- **eventID(s)** : fba6abf7-cdbc-4653-b7a7-e8b75e70f65f

### [CRITICAL] R08 - Trou de journalisation
- **Quand** : 2026-10-29T02:41:03Z | **Qui** : `bob` | **IP** : `203.0.113.66` | **Événement** : `StopLogging`
- **Détail** : Aucun événement de 2026-10-29T02:41:03Z à 2026-10-29T03:52:10Z (71 min). Cause probable : StopLogging par bob à 2026-10-29T02:41:03Z, redémarrage par alice (StartLogging). Toute action pendant ce créneau est INVISIBLE dans CloudTrail.
- **eventID(s)** : fba6abf7-cdbc-4653-b7a7-e8b75e70f65f, c7bf4fbc-d43c-4d6d-a0c1-ff1e20da8972

### [HIGH] R09 - Activité depuis une IP hors périmètre
- **Quand** : 2026-10-29T02:11:07Z | **Qui** : `bob` | **IP** : `203.0.113.66` | **Événement** : `ConsoleLogin`
- **Détail** : 14 événement(s) de bob depuis l'IP hors périmètre 203.0.113.66 (2026-10-29T02:11:07Z -> 2026-10-29T02:41:03Z) : ConsoleLoginx4, ListUsersx1, ListRolesx1, GetBucketPolicyx1, GetObjectx1, AttachUserPolicyx1
- **eventID(s)** : 4970ed9a-09ce-4cfb-a339-ba1925637cc3, b49e04cc-c243-49e7-a387-eaf6d4c3a832, 41843b03-04dd-4054-9448-23f7e7e646c7, 871c0884-9bdf-40f2-ba2c-0f19f0b2a5d1, b7f28572-3def-4849-9336-4f7e83efa9f3, 40ef3935-5f90-4ed6-bb25-664d630aa767 ...

### [HIGH] R03 - Clé d'accès non autorisée / usage suspect
- **Quand** : 2026-10-29T02:26:48Z | **Qui** : `svc-backup` | **IP** : `203.0.113.66` | **Événement** : `GetCallerIdentity`
- **Détail** : Clé AKIALABROGUE00000001 (créée à 2026-10-29T02:23:15Z par bob) utilisée depuis l'IP externe 203.0.113.66 (GetCallerIdentity)
- **eventID(s)** : ca9e4a62-fae3-414b-a3b4-42bd46494296

### [MEDIUM] R04 - Suppression de bucket S3
- **Quand** : 2026-10-28T11:50:27Z | **Qui** : `alice` | **IP** : `198.51.100.10` | **Événement** : `DeleteBucket`
- **Détail** : alice a supprimé le bucket 'tmp-test-bucket-7f3a' depuis 198.51.100.10
- **eventID(s)** : d6016237-ac9e-4156-b63f-ce413a9aca5e

### [MEDIUM] R09 - Activité depuis une IP hors périmètre
- **Quand** : 2026-10-29T02:26:48Z | **Qui** : `svc-backup` | **IP** : `203.0.113.66` | **Événement** : `GetCallerIdentity`
- **Détail** : 1 événement(s) de svc-backup depuis l'IP hors périmètre 203.0.113.66 (2026-10-29T02:26:48Z -> 2026-10-29T02:26:48Z) : GetCallerIdentityx1
- **eventID(s)** : ca9e4a62-fae3-414b-a3b4-42bd46494296

## 4. Alertes LOW / INFO (à trier - candidats faux positifs)

| Sév. | Règle | Heure | Principal | Détail |
|---|---|---|---|---|
| LOW | R06 | 2026-10-28T14:20:09Z | carol | carol : ListUsers refusé (AccessDenied) depuis 198.51.100.31 |
| LOW | R06 | 2026-10-29T02:16:02Z | bob | bob : ListUsers refusé (AccessDenied) depuis 203.0.113.66 |
| LOW | R06 | 2026-10-29T02:16:40Z | bob | bob : ListRoles refusé (AccessDenied) depuis 203.0.113.66 |
| LOW | R06 | 2026-10-29T02:17:25Z | bob | bob : GetBucketPolicy refusé (AccessDenied) depuis 203.0.113.66 |
| LOW | R06 | 2026-10-29T02:18:03Z | bob | bob : GetObject refusé (AccessDenied) depuis 203.0.113.66 |
| LOW | R06 | 2026-10-29T02:39:20Z | bob | bob : DeleteTrail refusé (AccessDeniedException) depuis 203.0.113.66 |
| INFO | R03 | 2026-10-28T09:32:10Z | alice | alice crée une clé pour lui-même depuis une IP interne (rotation probable : à vérifier) |

## 5. Chronologie de l'incident (activité des IP externes suspectes)

IP suspectes : `203.0.113.66`

| Heure (UTC) | Principal | Événement | Résultat | IP |
|---|---|---|---|---|
| 2026-10-29T02:11:07Z | bob | ConsoleLogin | Failure | 203.0.113.66 |
| 2026-10-29T02:11:31Z | bob | ConsoleLogin | Failure | 203.0.113.66 |
| 2026-10-29T02:11:52Z | bob | ConsoleLogin | Failure | 203.0.113.66 |
| 2026-10-29T02:14:30Z | bob | ConsoleLogin | Success | 203.0.113.66 |
| 2026-10-29T02:16:02Z | bob | ListUsers | AccessDenied | 203.0.113.66 |
| 2026-10-29T02:16:40Z | bob | ListRoles | AccessDenied | 203.0.113.66 |
| 2026-10-29T02:17:25Z | bob | GetBucketPolicy | AccessDenied | 203.0.113.66 |
| 2026-10-29T02:18:03Z | bob | GetObject | AccessDenied | 203.0.113.66 |
| 2026-10-29T02:21:40Z | bob | AttachUserPolicy | OK | 203.0.113.66 |
| 2026-10-29T02:23:15Z | bob | CreateAccessKey | OK | 203.0.113.66 |
| 2026-10-29T02:26:48Z | svc-backup | GetCallerIdentity | OK | 203.0.113.66 |
| 2026-10-29T02:31:12Z | bob | ListBuckets | OK | 203.0.113.66 |
| 2026-10-29T02:33:05Z | bob | DeleteBucket | OK | 203.0.113.66 |
| 2026-10-29T02:39:20Z | bob | DeleteTrail | AccessDeniedException | 203.0.113.66 |
| 2026-10-29T02:41:03Z | bob | StopLogging | OK | 203.0.113.66 |

## 6. Fenêtres de journalisation interrompue

- [CRITICAL] Aucun événement de 2026-10-29T02:41:03Z à 2026-10-29T03:52:10Z (71 min). Cause probable : StopLogging par bob à 2026-10-29T02:41:03Z, redémarrage par alice (StartLogging). Toute action pendant ce créneau est INVISIBLE dans CloudTrail.

## 7. Mesures correctives recommandées (par règle déclenchée)

- **R01 - Connexion console sans MFA** : Imposer le MFA à tous les utilisateurs IAM (politique deny-sans-MFA), réinitialiser le mot de passe du compte, révoquer les sessions actives, privilégier IAM Identity Center.
- **R02 - Attribution de privilèges administrateur** : Détacher la politique, retirer iam:AttachUserPolicy aux non-administrateurs, définir une permissions boundary / SCP interdisant l'auto-élévation, alerter en temps réel (EventBridge).
- **R03 - Clé d'accès non autorisée / usage suspect** : Désactiver puis supprimer la clé, auditer toutes les actions faites avec, limiter iam:CreateAccessKey (Condition aws:username), préférer des rôles/sessions temporaires aux clés longues.
- **R04 - Suppression de bucket S3** : Activer versioning + MFA Delete + Object Lock sur les buckets critiques, répliquer vers un autre compte, restreindre s3:DeleteBucket, restaurer depuis la sauvegarde isolée.
- **R05 - Altération de la journalisation CloudTrail** : Relancer la trail, protéger cloudtrail:StopLogging/DeleteTrail/UpdateTrail par SCP (Organizations), trail multi-région + validation d'intégrité des fichiers, copie des logs vers un compte de logs dédié.
- **R06 - Accès refusé(s) à des ressources** : Investiguer l'identité source, vérifier la légitimité du besoin, appliquer le moindre privilège, ajouter une alerte de seuil sur les AccessDenied.
- **R07 - Échecs de connexion console répétés** : Verrouiller/surveiller le compte, imposer MFA, filtrer par IP source, activer des alertes sur ConsoleLogin=Failure, réinitialiser le mot de passe si succès consécutif.
- **R08 - Trou de journalisation** : Déterminer la cause (StopLogging ? panne ?), relancer la trail, reconstituer l'activité avec d'autres sources (S3 server access logs, GuardDuty, VPC Flow Logs, CloudWatch), alarme IsLogging=false.
- **R09 - Activité depuis une IP hors périmètre** : Vérifier la géolocalisation/ASN, restreindre par condition aws:SourceIp, révoquer les identifiants concernés, enrichir avec une liste d'IP de confiance.

## 8. Limites de l'analyse

- Règles à seuils fixes : elles n'identifient pas tout et génèrent des faux positifs (cf. section 4).
- Un attaquant qui coupe la journalisation rend ses actions invisibles : croiser avec d'autres sources.
- Les événements de données S3 n'existent que si les *data events* sont activés sur la trail.
- Les verdicts sont des **hypothèses d'investigation**, à confirmer auprès des personnes concernées.
