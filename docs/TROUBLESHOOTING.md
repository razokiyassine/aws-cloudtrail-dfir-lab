# Troubleshooting (observed during this lab)

## Docker is installed, but `docker compose` is missing

Docker Engine and Docker Compose are different packages. On Debian, install the Compose v2 CLI plugin from the official Docker distribution or a compatible plugin release. Verify:

```bash
docker --version
docker compose version
```

Avoid installing arbitrary binaries from untrusted websites. If a download was interrupted, `chmod +x` cannot repair an incomplete binary.

## `Temporary failure resolving 'deb.debian.org'` during Docker build

The host resolved the domain, but the Docker bridge/build network did not. Diagnostic comparison:

```bash
getent ahostsv4 deb.debian.org
docker run --rm python:3.12-slim python -c 'import socket;print(socket.gethostbyname("deb.debian.org"))'
docker run --rm --network host python:3.12-slim python -c 'import socket;print(socket.gethostbyname("deb.debian.org"))'
```

In the observed run, the second command failed and the third succeeded. The **optional build-only** overlay resolved the build:

```bash
docker compose -f docker-compose.yml -f docker-compose.dns-fix.yml build lab
docker compose up -d --no-build
```

A later plain `docker compose up -d --build` failed again because it omitted the overlay. To rebuild with the fix, always pass both `-f` files, or locally copy the overlay to `docker-compose.override.yml` (**that local override should not be committed without review**).

This technique is a workaround for the observed host and should not replace proper DNS/network configuration on production nodes.

## AWS CLI cannot connect to `http://localstack:4566`

Make sure commands run **inside** the analysis container:

```bash
# Docker host:
docker compose exec lab bash
# Inside lab:
aws sts get-caller-identity
aws s3 ls
```

`localstack` is an internal Docker DNS hostname; it generally does not resolve directly on the Debian host. The host AWS CLI may also lack dummy credentials. **Do not configure real AWS keys for this lab.**

## Host cannot write into `rendu/traces`: Permission denied

A directory created in the container by `root` can be root-owned on the bind-mounted host. Prefer writing from inside the `lab` container, or change ownership on the **specific lab output directory**:

```bash
sudo chown -R "$USER":"$USER" ./rendu
```

Do not recursively chown Docker's system paths.

## LocalStack CloudTrail `StopLogging` fails

`cloudtrail` is not supplied by this LocalStack Community configuration. An API failure for `StopLogging` is expected, not proof of successful IAM enforcement. The successful `StopLogging` in the 265-event investigation is **synthetic**.

## `aws s3 ls` shows missing backup bucket after simulation

The local activity script deletes `corp-backups-prod`. Recreate the resources from **inside `lab`**:

```bash
bash scripts/01_init_aws_local.sh
```

The IAM changes persist: Bob may still have AdministratorAccess and svc-backup may still have two keys. For a full LocalStack-only reset, stop the stack and remove the named volume:

```bash
# Warning: destroys lab emulator state
exit
docker compose down -v
```

## The reports suddenly contain many Medium alerts

The `--gap-minutes 5` experiment produces many R08 gap findings due to normal 10-minute intervals. Restore the default 30-minute report:

```bash
bash scripts/04_collect_and_analyze.sh
```
