# Reproduce the CloudTrail lab

## Requirements

- Docker Engine or Docker Desktop, plus Docker Compose v2 (`docker compose version`).
- Enough free memory/disk for LocalStack and Python images (4 GiB RAM for the lab machine is recommended in our tested setup).
- Internet for Docker image pulls and building the analysis container.
- **No actual AWS account, card or permanent credentials needed.**

## Build and start

```bash
cp .env.example .env
# Ensure LOCALSTACK_IMAGE=localstack/localstack:4.14
# Ensure LOCALSTACK_AUTH_TOKEN= (empty)
docker compose up -d --build
docker compose ps
```

If Docker build cannot resolve Debian's repositories, do **not** repeatedly invoke `up --build`; follow [the documented DNS fix](TROUBLESHOOTING.md) first.

Run this only on the container **host**:

```bash
docker compose exec lab bash
```

The rest of the commands are **inside** `/lab`, not on the Docker host:

```bash
aws --version
python --version
jq --version
bash scripts/00_check_env.sh
bash scripts/01_init_aws_local.sh
aws s3 ls
aws iam list-users --query 'Users[].UserName' --output text
```

Expect 4 buckets and 4 IAM users. CloudTrail is **not** available; that is an expected limitation.

## Local simulation (changes emulator state)

```bash
bash scripts/02_generate_activity.sh
```

The script attaches AdministratorAccess to Bob, creates an additional key for `svc-backup`, deletes the backup bucket, attempts unsupported StopLogging and triggers NoSuchKey. Restore the deleted bucket:

```bash
bash scripts/01_init_aws_local.sh
```

This restores sample S3 resources but **does not** revoke the IAM changes. To reset all emulator state, run on the Docker host:

```bash
docker compose down -v   # DANGER: deletes the named LocalStack volume and its lab state
```

## Synthetic log pipeline

Inside `lab`:

```bash
python src/generate_events.py --seed 42
python scripts/verify_fixture.py
bash scripts/03_upload_logs.sh
bash scripts/04_collect_and_analyze.sh
cat reports/analysis_report.md
```

`generate_events.py` also creates `teacher/answer_key.json` by default; this must stay **private and out of Git**. The file is ignored by `.gitignore`. Treat the source-supplied fixture (`data/`) and reports as **educational synthetic data**.

## Python-only analysis

When Docker is unavailable, the synthetic pipeline can run without AWS:

```bash
python src/generate_events.py --seed 42
python src/analyze_logs.py data/s3_layout
python -m unittest discover -s tests -v
```

## Capture native LocalStack request logs

On the **Docker host**:

```bash
docker logs lab-localstack > localstack-native.log 2>&1
# Optional conversion, using the running analysis container:
docker logs lab-localstack 2>&1 | docker compose exec -T lab python src/parse_localstack_logs.py -
```

Native request logs confirm emulated API calls, not CloudTrail identities. Do not include local logs with secrets or personal information in a public repository.
