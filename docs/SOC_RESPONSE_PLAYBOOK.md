# Cloud incident response playbook (educational)

**Trigger:** unusual console login without MFA and subsequent IAM/S3 changes. **Scope:** this lab's *synthetic* event stream, not a live AWS incident.

## Triage

1. Find the actor via `userIdentity` and verify `eventTime` (UTC), `eventName`, source IP and account.
2. Group events by access-key ID and `eventID`.
3. Check whether repeated denied requests precede privilege changes.
4. Confirm suspected changes from logs **and** live configuration when a real environment is available.

## Containment checklist (example real-world actions)

- [ ] Assign an incident owner and preserve available original logs.
- [ ] Disable unexpected keys and examine their use prior to deletion.
- [ ] Revoke suspicious sessions and rotate affected credentials.
- [ ] Remove unapproved administrator policies and inspect other IAM changes.
- [ ] Verify logging status and restore central log delivery.
- [ ] Assess affected backups and restore from an isolated trustworthy copy.
- [ ] Establish what remains unknown during any logging blackout.

## Recovery and lessons learned

Implement MFA, roles with temporary credentials, least-privilege IAM permissions, strong SCP coverage, immutable isolated backups and independent logging health alerts. Re-test the rules with expected benign cases.

## Evidence hygiene

Keep a copy of original evidence, document timestamps and transformations and separate *observed native LocalStack requests* from *generated synthetic CloudTrail events*. The student-run LocalStack re-initialization restored the bucket but did **not** revoke the simulated IAM changes; the response steps by Alice appear in the synthetic dataset only.
