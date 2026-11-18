# Detection engineering: R01–R09

The detection engine is `src/analyze_logs.py`. Findings are written to `reports/analysis_report.md`, `reports/findings.json` and `reports/findings.csv` when executed.

| Rule | Signal | Key observation (synthetic) | Potential limitation |
| --- | --- | --- | --- |
| R01 | Successful `ConsoleLogin` without MFA | Bob login at 02:14:30Z | Non-MFA login alone needs context |
| R02 | `AttachUserPolicy` granting AdministratorAccess | Bob admin self-elevation | Other IAM escalation techniques may be missed |
| R03 | Key created for another identity or suspicious use | New `svc-backup` key | Legitimate key rotation can look similar |
| R04 | S3 `DeleteBucket` | Production backup bucket removed | A test bucket deletion may be benign |
| R05 | CloudTrail modification/disable attempt | Denied `DeleteTrail`; successful `StopLogging` | Synthetic only in this exercise |
| R06 | Denied actions, including a burst | Four IAM/S3 denials | A single AccessDenied may be harmless |
| R07 | Repeated failed console logins | Three failures followed by success | Repeated human mistakes can occur |
| R08 | Gap between successive log events | 71-min silence | Low-volume systems naturally produce gaps |
| R09 | API activity from IP outside configured perimeter | 203.0.113.66 | Need trustworthy baseline CIDRs / network context |

## Results at the default threshold

| Severity | Count |
| --- | ---: |
| CRITICAL | 9 |
| HIGH | 2 |
| MEDIUM | 2 |
| LOW | 6 |
| INFO | 1 |

These are **20 findings, not 20 distinct attackers or incidents**. Different rules can correlate to the same `eventID`.

## Tuning experiment: gap rule R08

Observed from the supplied 265-event deterministic fixture:

| Gap threshold | CRITICAL | MEDIUM | Lesson |
| --- | ---: | ---: | --- |
| 5 min | 9 | 126 | Many normal monitoring intervals trigger alerts (noise) |
| 30 min | 9 | 2 | Detects the 71-min gap with limited noise in this fixture |
| 120 min | 8 | 2 | Misses the critical 71-min logging gap |

Commands:

```bash
python src/analyze_logs.py collected --gap-minutes 5
python src/analyze_logs.py collected --gap-minutes 120
bash scripts/04_collect_and_analyze.sh   # restore default report outputs
```

**Interpretation:** this lab illustrates false-positive / false-negative trade-offs. The best production threshold must be based on the source's normal event cadence, business criticality and independent logging health signals. This project has no real-time SIEM ingestion.

## Improvement ideas (not implemented)

- Correlate `StopLogging` with an absent health heartbeat and a recovery event, rather than treating every generic event gap equally.
- Detect `PutUserPolicy`, `CreatePolicyVersion`, `SetDefaultPolicyVersion`, role trust-policy modifications and permissions-boundary changes.
- Enrich external IPs with approved CIDR lists and explicit change windows.
- Store rule tests with expected output and false-positive controls.
- Ship results into an open-source SIEM for dashboards and case management.
