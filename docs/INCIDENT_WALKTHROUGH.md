# Incident investigation — synthetic case study

> **Evidence provenance**: All entries below come from the **synthetic CloudTrail-format fixture** included in this educational project. Times refer to **2026-10-29 UTC**, not the date on which LocalStack API operations were executed. `203.0.113.66` is a documentation-range IP, not a real attributed attacker.

## Executive summary

The dataset suggests probable compromise of IAM user `bob` after repeated login failures and a successful console login without MFA from an out-of-perimeter IP. The actor then performs IAM/S3 reconnaissance, obtains AdministratorAccess, creates a new key for `svc-backup`, deletes the production backup bucket and suppresses the CloudTrail-like logging feed for approximately 71 minutes. A later response sequence attributed to `alice` restarts logging, disables the suspicious key and detaches the admin policy.

## Attack timeline with evidence IDs

| Time UTC | Actor | Event | Case | `eventID` |
| --- | --- | --- | --- | --- |
| 02:11:07 | bob | ConsoleLogin failure | S5 | `4970ed9a-09ce-4cfb-a339-ba1925637cc3` |
| 02:11:31 | bob | ConsoleLogin failure | S5 | `b49e04cc-c243-49e7-a387-eaf6d4c3a832` |
| 02:11:52 | bob | ConsoleLogin failure | S5 | `41843b03-04dd-4054-9448-23f7e7e646c7` |
| 02:14:30 | bob | ConsoleLogin success, no MFA | S5 | `871c0884-9bdf-40f2-ba2c-0f19f0b2a5d1` |
| 02:16:02 | bob | ListUsers AccessDenied | S6 | `b7f28572-3def-4849-9336-4f7e83efa9f3` |
| 02:16:40 | bob | ListRoles AccessDenied | S6 | `40ef3935-5f90-4ed6-bb25-664d630aa767` |
| 02:17:25 | bob | GetBucketPolicy AccessDenied | S6 | `10275b53-2285-42ef-8fbe-4fe92ea9c542` |
| 02:18:03 | bob | GetObject AccessDenied | S6 | `0c3ce284-c7e5-4bbb-9cb5-1c535b62a8df` |
| 02:21:40 | bob | AttachUserPolicy AdministratorAccess | S2 | `6cac028c-ba22-4065-9526-0718cd180a82` |
| 02:23:15 | bob | CreateAccessKey for svc-backup | S1 | `e95f176c-deba-4186-ba10-82170ad7c9a2` |
| 02:26:48 | svc-backup | GetCallerIdentity with new key | S1 | `ca9e4a62-fae3-414b-a3b4-42bd46494296` |
| 02:31:12 | bob | ListBuckets | S3 | `add702c9-2747-493c-9ae7-7eab084a6780` |
| 02:33:05 | bob | DeleteBucket corp-backups-prod | S3 | `1e2595b8-8fc9-486b-a9dd-ebf563119aca` |
| 02:39:20 | bob | DeleteTrail denied by SCP | S4 | `51d08109-fc90-4838-9874-1408f7b217c7` |
| 02:41:03 | bob | StopLogging successful | S4 | `fba6abf7-cdbc-4653-b7a7-e8b75e70f65f` |
| 03:52:10 | alice | StartLogging | Response | `c7bf4fbc-d43c-4d6d-a0c1-ff1e20da8972` |
| 03:58:30 | alice | UpdateAccessKey | Response | `46426c45-8d03-417a-b4d3-75c1a29319fa` |
| 04:02:14 | alice | DetachUserPolicy | Response | `e3954cb1-7f7f-4c0a-87c0-d116a394ed54` |

The visible event gap runs from `02:41:03Z` until `03:52:10Z` — 71 minutes and 7 seconds. **No assertion about actions inside the gap can be supported by this evidence source alone.**

## Six connected scenarios

| Scenario | Core issue | Evidence | Defensive priority |
| --- | --- | --- | --- |
| S5 | Initial account access with no MFA | Three failures + one success | MFA, session revocation, login monitoring |
| S6 | Discovery and denied requests | Four denied IAM/S3 API calls | Least privilege, denied-call correlation |
| S2 | Privilege escalation | `AttachUserPolicy` | Remove admin rights, restrict IAM modification |
| S1 | Persistence through secondary credentials | `CreateAccessKey` and subsequent use | Disable and rotate compromised keys |
| S3 | Backup data destruction | `DeleteBucket` | Object Lock/versioning, isolated backups, restricted delete |
| S4 | Defense impairment | `DeleteTrail` denied; `StopLogging` success | SCP guardrails, logging integrity and health monitoring |

## Key indicators (lab-only)

- Synthetic source IP: `203.0.113.66` (TEST-NET-3).
- Accounts: `bob` and `svc-backup`.
- Synthetic rogue access key: `AKIALABROGUE00000001` (not a real AWS key).
- Deleted bucket: `corp-backups-prod`.
- Trail identifier: `corp-trail`.
- Evidence identifiers: the `eventID`s above.

## Root causes and context

1. No MFA at the suspicious successful console login.
2. Over-permissive `config/dev-policy.json`: wildcard `iam:AttachUserPolicy`, `iam:CreateAccessKey`, `s3:*`.
3. Incomplete preventive guardrail: SCP blocks `DeleteTrail` but not `StopLogging` **in the synthetic case**.
4. Insufficient isolation and protection of critical backups.

An `AccessDenied` is not automatically malicious: in this case, frequency, source IP, the preceding login and later IAM changes make the denial burst suspicious.

## Corrective recommendations

**Containment:** revoke sessions, reset compromised credentials, disable the extra svc-backup key and remove the excess policy. **Recovery:** verify logging status and backup integrity. **Prevention:** mandatory MFA, IAM least privilege, restrictive SCPs for logging, immutable/off-account backups. **Detection:** correlated rules for MFA, unusual IPs, IAM modifications, backup deletion and log-health monitoring.

## Uncertainty and limits

- The log stream and actor attribution are **synthetic**; LocalStack native traces prove API operations were accepted by the emulator, not the complete identity context described here.
- No real AWS account or CloudTrail trail was used.
- No comprehensive S3 data event coverage is provided.
- The missing 71-minute interval may contain unknown activity.
- The response actions by Alice occur in the synthetic dataset; the student's actual LocalStack restoration only recreated the removed S3 bucket and did not automatically revoke IAM modifications.
