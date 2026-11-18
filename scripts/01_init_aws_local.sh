#!/usr/bin/env bash
# 01_init_aws_local.sh - Crée l'infrastructure fictive dans LocalStack : buckets, utilisateurs IAM, politiques.
# Idempotent (peut être relancé). Exécution :  bash scripts/01_init_aws_local.sh
source "$(dirname "$0")/lib.sh"
REGION="$AWS_DEFAULT_REGION"

mk_bucket() {
  if aws_ s3api head-bucket --bucket "$1" 2>/dev/null; then echo "  bucket déjà présent : $1"
  else aws_ s3api create-bucket --bucket "$1" --region "$REGION" \
        --create-bucket-configuration LocationConstraint="$REGION" >/dev/null && ok "bucket créé : $1"; fi
}

say "Buckets S3"
for b in corp-app-data corp-backups-prod corp-finance-secrets "$LOG_BUCKET"; do mk_bucket "$b"; done

say "Objets d'exemple"
echo "id;montant" > /tmp/payroll.csv && echo "1;4200" >> /tmp/payroll.csv
echo "dump-simule" > /tmp/db.dump
aws_ s3 cp /tmp/payroll.csv s3://corp-finance-secrets/2026/payroll.csv >/dev/null && ok "payroll.csv"
aws_ s3 cp /tmp/db.dump     s3://corp-backups-prod/daily/db-00.dump   >/dev/null && ok "db-00.dump"

say "Utilisateurs IAM"
for u in alice bob carol svc-backup; do
  aws_ iam create-user --user-name "$u" >/dev/null 2>&1 && ok "utilisateur créé : $u" || echo "  déjà présent : $u"
done

say "Politique volontairement TROP permissive pour bob (point de départ de l'incident)"
POL_ARN=$(aws_ iam create-policy --policy-name DevPolicy --policy-document file://config/dev-policy.json \
          --query Policy.Arn --output text 2>/dev/null || true)
[ -z "$POL_ARN" ] && POL_ARN="arn:aws:iam::000000000000:policy/DevPolicy"
aws_ iam attach-user-policy --user-name bob --policy-arn "$POL_ARN" && ok "DevPolicy attachée à bob : $POL_ARN"

say "ReadOnlyAccess pour carol (politique gérée AWS)"
aws_ iam attach-user-policy --user-name carol --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess \
  && ok "ReadOnlyAccess attachée à carol" || warn "politique gérée non disponible : voir README, section 'plan B'"

say "Clé d'accès légitime du compte de service"
if [ -z "$(aws_ iam list-access-keys --user-name svc-backup --query 'AccessKeyMetadata[]' --output text)" ]; then
  aws_ iam create-access-key --user-name svc-backup --query 'AccessKey.AccessKeyId' --output text
else
  aws_ iam list-access-keys --user-name svc-backup --query 'AccessKeyMetadata[].AccessKeyId' --output text
fi

say "Terminé. Récapitulatif :"
aws_ s3 ls; aws_ iam list-users --query 'Users[].UserName' --output text
