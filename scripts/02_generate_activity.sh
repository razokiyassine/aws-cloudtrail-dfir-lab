#!/usr/bin/env bash
# 02_generate_activity.sh - Rejoue, avec de VRAIS appels d'API sur LocalStack, une version réduite de l'attaque.
#
# IMPORTANT - ce qui est réel et ce qui ne l'est pas :
#  * Les actions ci-dessous modifient réellement l'état de LocalStack (clé créée, politique attachée, bucket supprimé).
#  * Elles ne produisent AUCUN enregistrement CloudTrail (service absent de l'édition gratuite).
#  * LocalStack gratuit n'applique pas les politiques IAM : aucun "AccessDenied" réel n'est produit.
#  * Seules traces réelles : les lignes "AWS <service>.<opération> => <code>" dans `docker logs lab-localstack`.
source "$(dirname "$0")/lib.sh"

say "S2 - Attribution d'AdministratorAccess à bob"
aws_ iam attach-user-policy --user-name bob --policy-arn arn:aws:iam::aws:policy/AdministratorAccess \
  && ok "AdministratorAccess attachée à bob" || ko "échec (voir README, plan B)"

say "S1 - Création d'une clé d'accès pour svc-backup (identité différente de l'acteur)"
aws_ iam create-access-key --user-name svc-backup --query 'AccessKey.{Id:AccessKeyId,Status:Status}' --output table

say "S3 - Suppression du bucket corp-backups-prod"
aws_ s3 rb s3://corp-backups-prod --force && ok "bucket supprimé (relancer 01_init_aws_local.sh pour le recréer)"

say "S4 - Tentative d'arrêt de CloudTrail (échec attendu : service non émulé)"
aws_ cloudtrail stop-logging --name corp-trail 2>&1 | head -c 400; echo
warn "Cette commande échoue ICI. L'événement StopLogging du TP vient du jeu de données SYNTHÉTIQUE."

say "S6 - Lecture d'un objet inexistant (404 réel, mais PAS un AccessDenied)"
aws_ s3api get-object --bucket corp-finance-secrets --key inexistant.xlsx /tmp/x 2>&1 | head -c 300; echo

say "Suite : exporter les traces réelles de LocalStack"
echo "  (hôte)  docker logs lab-localstack 2>&1 | docker compose exec -T lab python src/parse_localstack_logs.py -"
