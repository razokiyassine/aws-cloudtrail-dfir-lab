# Verified lab findings

## Dataset

- Total synthetic records: **265**.
- Background and decoys: **247**.
- Attack / response records: **18**.
- CloudTrail-like compressed objects: **114**.
- LocalStack native request lines were also converted to 76 simplified records during the exercise; **they are not CloudTrail**.

## Detection at 30-minute gap threshold

| Severity | Count |
|---|---:|
| CRITICAL | 9 |
| HIGH | 2 |
| MEDIUM | 2 |
| LOW | 6 |
| INFO | 1 |
| **Total** | **20** |

These are findings, not 20 independent intrusions.

## Sensitivity of logging-gap detection (R08)

| Gap threshold | Critical | Medium | Interpretation |
|---|---:|---:|---|
| 5 minutes | 9 | 126 | Excessive alerts between normal periodic events |
| 30 minutes | 9 | 2 | Detects the ~71-minute gap with less noise |
| 120 minutes | 8 | 2 | Misses the ~71-minute gap |

## High-confidence observations from synthetic evidence

- Bob: repeated login failures then success **without MFA** from `203.0.113.66`.
- Bob: `AttachUserPolicy` granting AdministratorAccess.
- Bob: `CreateAccessKey` for the separate identity `svc-backup`; subsequent use of the new key.
- Bob: `DeleteBucket` targeting `corp-backups-prod`.
- Bob: `DeleteTrail` denied by explicit SCP but `StopLogging` succeeded **in the synthetic timeline**.
- Alice: logging restoration and IAM containment actions.

Never infer absence of attacker actions during a logging gap from the lack of events alone.
