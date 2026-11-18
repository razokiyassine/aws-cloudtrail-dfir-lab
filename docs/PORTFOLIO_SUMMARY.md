# Portfolio project summary

**Title:** AWS CloudTrail DFIR Lab — IAM/S3 Attack Detection & Investigation

**Technical scope:** Python, AWS CLI, LocalStack, Docker Compose, S3, IAM, STS, JSON/jq, rule-based detection, evidence correlation.

**What was executed:** provisioned an isolated AWS-like local environment; validated S3/IAM/STS; manipulated sample storage and permissions; generated, uploaded and collected deterministic synthetic CloudTrail-like records; applied nine detection rules; analyzed 20 findings; investigated six connected scenarios and documented incident-response recommendations.

**Results:** 265 synthetic events; 114 gzip JSON log files; 9 CRITICAL, 2 HIGH, 2 MEDIUM, 6 LOW, 1 INFO alerts using default tuning; investigated ~71-minute synthetic logging gap.

**Integrity statement:** Native S3/IAM operations were run against LocalStack. CloudTrail was not available; the CloudTrail-style evidence and its successful logging-disable operation were synthetic.

**Suggested resume bullet:** “Implemented and documented a local Cloud Security DFIR workflow using AWS-style S3/IAM APIs, Python log collection and nine detection rules; investigated a deterministic 265-event synthetic CloudTrail scenario with evidence-linked chronology and false-positive tuning.”
