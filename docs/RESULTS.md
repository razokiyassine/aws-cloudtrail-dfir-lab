# Verified lab results

## Environment

- 2 Compose services started: `lab-shell` and `lab-localstack` (LocalStack 4.14.0 healthy).
- S3, IAM and STS emulated successfully; CloudTrail unavailable as expected.
- Four S3 buckets and four IAM users initialized.
- A local demonstration attached `AdministratorAccess` to Bob, created an extra svc-backup key and removed the backup bucket; subsequent re-initialization recreated its bucket and sample object.
- Native LocalStack request logs were parsed into **76 minimal request records** in the observed execution; they are not real CloudTrail records.

## Synthetic pipeline

- `seed=42` produced **265** CloudTrail-like events: 247 background/decoy and 18 attack/response.
- 114 compressed `.json.gz` files generated and uploaded to locally emulated S3.
- 114 files successfully downloaded and **265 unique events** analyzed.
- Detection counts: CRITICAL=9, HIGH=2, MEDIUM=2, LOW=6, INFO=1.
- A **71-minute** logging gap was identified.
- Local test with `--gap-minutes 5`: 9 Critical, 126 Medium.
- Local test with `--gap-minutes 120`: 8 Critical, 2 Medium (missed 71-minute R08 case).

## Sample output files

- [`examples/reports/analysis_report.md`](../examples/reports/analysis_report.md)
- [`examples/reports/findings.json`](../examples/reports/findings.json)
- [`examples/reports/findings.csv`](../examples/reports/findings.csv)

These files are sample outputs included with the original educational starter, consistent with the reproducible seed-42 fixture. They are not production telemetry.

## Unit test coverage

The original `tests/test_pipeline.py` has six tests: deterministic generation, detection across all six scenarios, decoy false-positive constraint, logging gap alert, no events during the gap and CloudTrail core fields. Execute:

```bash
python -m unittest discover -s tests -v
python scripts/verify_fixture.py
```

## Screenshots

Selected user-run screenshots are in [`docs/screenshots/`](screenshots/README.md). They demonstrate container startup, initialization, S3 access, API actions, findings, tuning and investigation. Treat image captures as evidence of what the lab terminal displayed — **not independent proof of a real AWS account compromise**.
