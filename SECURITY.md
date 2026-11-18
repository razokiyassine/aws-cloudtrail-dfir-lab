# Security policy / educational scope

This repository intentionally includes an **over-permissive IAM policy** and scripts that modify a local S3/IAM emulator. They are **teaching examples**, not recommended production configurations.

- Run only against your own isolated LocalStack environment.
- Do not commit `.env`, AWS credentials, access tokens, private keys or actual workplace logs.
- A generated `teacher/answer_key.json` is excluded by `.gitignore`; do not distribute it.
- CloudTrail-format logs in `data/` are synthetic. Do not use them as evidence of a real external attack.
- The CI workflow runs local Python tests only and needs no secrets.

Please report any accidental real credential exposure privately to the repository maintainer; revoke the exposed credential immediately.
