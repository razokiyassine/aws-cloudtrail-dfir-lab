#!/usr/bin/env bash
# 00_check_env.sh - Vérifie l'environnement et établit la "carte" réel / non disponible.
# Exécution (dans le conteneur) :  bash scripts/00_check_env.sh
source "$(dirname "$0")/lib.sh"

say "Attente du point d'accès AWS local : $LAB_ENDPOINT"
for i in $(seq 1 30); do
  if aws_ sts get-caller-identity >/dev/null 2>&1; then ok "Point d'accès joignable (essai $i)"; break; fi
  sleep 2
  [ "$i" = 30 ] && { ko "Injoignable. Vérifiez : docker compose ps / docker compose logs localstack"; exit 1; }
done

say "Identité (factice) vue par l'émulateur"
aws_ sts get-caller-identity

say "Services annoncés par LocalStack (si /_localstack/health existe)"
if curl -sf "$LAB_ENDPOINT/_localstack/health" >/tmp/health.json 2>/dev/null; then
  jq -r '.services | to_entries[] | "  \(.key): \(.value)"' /tmp/health.json
else
  warn "Pas d'endpoint health (normal avec moto)."
fi

say "Test des fonctionnalités utilisées par le TP"
aws_ s3api list-buckets >/dev/null 2>&1 && ok "S3  : disponible" || ko "S3  : indisponible"
aws_ iam list-users     >/dev/null 2>&1 && ok "IAM : disponible" || ko "IAM : indisponible"

if aws_ cloudtrail describe-trails >/tmp/ct.out 2>&1; then
  warn "CloudTrail répond ! (inhabituel en version gratuite) - vérifiez que ce sont de vrais événements avant de les utiliser."
else
  ok  "CloudTrail : NON disponible dans cette édition (comportement attendu) -> les journaux du TP seront SYNTHÉTIQUES."
  echo "    Message renvoyé : $(head -c 300 /tmp/ct.out | tr '\n' ' ')"
fi
