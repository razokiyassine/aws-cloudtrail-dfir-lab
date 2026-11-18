# Security and ethical scope

This is an **isolated educational lab**. It does not use an AWS account and must not be misrepresented as a production intrusion or real CloudTrail investigation.

- The IAM policy in `config/dev-policy.json` is **deliberately insecure**.
- Never execute the scripts against real AWS endpoints or production data.
- The helper script `scripts/lib.sh` restricts the lab to localhost, LocalStack or Moto.
- Do not commit `.env`, authentication tokens, cloud credentials or private log exports.
- Do not commit instructor solutions, including `teacher/answer_key.json`.
- The IP address `203.0.113.66` is from documentation-only address space.
- Synthetic CloudTrail records are not authoritative evidence of real AWS actions.

For vulnerability reports, privately contact the project maintainer. Do not post sensitive credentials or exploit details in public issues.
