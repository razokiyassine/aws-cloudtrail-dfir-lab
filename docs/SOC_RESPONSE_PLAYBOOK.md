# SOC playbook: suspicious Cloud IAM and logging activity

## Detection triggers

- Successful console access without MFA, especially after repeated failures.
- IAM `AttachUserPolicy` to AdministratorAccess.
- `CreateAccessKey` for a separate identity.
- Unexpected S3 backup deletion.
- `DeleteTrail`, `StopLogging` or abnormal interruption of CloudTrail delivery.
- IAM/S3 discovery and repeated denied actions from an unfamiliar IP.

## Analyst triage

1. Confirm log provenance (real CloudTrail vs synthetic / LocalStack diagnostic).
2. Identify actor, key, IP, `eventName`, resource, UTC time and `eventID`.
3. Compare with normal user role, approved changes and MFA posture.
4. Correlate events to reconstruct a full sequence; investigate benign alternatives.
5. Assign severity based on privilege, persistence, backup impact and loss of visibility.

## Response priorities

**Contain:** disable suspect access keys, remove unauthorized permissions, revoke affected sessions and require MFA.

**Recover:** verify logging has resumed; restore backup services from protected copies.

**Harden:** least-privilege IAM, restrict access-key creation, SCP coverage for both trail deletion and stopping logs, immutable logging and separate backup access.

**Preserve evidence:** record UTC timeline, eventIDs, relevant JSON, collection method and known observation gaps.

## Limitations

Do not claim that the absence of log records proves no activity. This educational dataset does not provide independent VPC Flow Logs, object-level S3 events for every operation or production evidence chain of custody.
