#!/usr/bin/env bash
# 03_upload_logs.sh - Dépose les journaux SYNTHÉTIQUES dans un bucket S3 LocalStack, avec la même disposition
# que la livraison réelle de CloudTrail (AWSLogs/<compte>/CloudTrail/<région>/AAAA/MM/JJ/*.json.gz).
source "$(dirname "$0")/lib.sh"
[ -d data/s3_layout ] || { ko "data/s3_layout absent : lancez d'abord  python src/generate_events.py"; exit 1; }
aws_ s3api head-bucket --bucket "$LOG_BUCKET" 2>/dev/null || \
  aws_ s3api create-bucket --bucket "$LOG_BUCKET" --region "$AWS_DEFAULT_REGION" \
       --create-bucket-configuration LocationConstraint="$AWS_DEFAULT_REGION" >/dev/null
say "Envoi vers s3://$LOG_BUCKET/"
aws_ s3 sync data/s3_layout "s3://$LOG_BUCKET/" --only-show-errors
ok "$(aws_ s3 ls "s3://$LOG_BUCKET/" --recursive | wc -l) objet(s) dans le bucket"
aws_ s3 ls "s3://$LOG_BUCKET/AWSLogs/000000000000/CloudTrail/"
