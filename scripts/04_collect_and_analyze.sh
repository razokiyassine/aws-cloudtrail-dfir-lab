#!/usr/bin/env bash
# 04_collect_and_analyze.sh - Collecte les journaux depuis S3 (comme le ferait un SIRT) puis lance l'analyse.
source "$(dirname "$0")/lib.sh"
rm -rf collected && mkdir -p collected
say "Collecte : s3://$LOG_BUCKET -> ./collected"
aws_ s3 sync "s3://$LOG_BUCKET/" collected --only-show-errors
ok "$(find collected -name '*.json.gz' | wc -l) fichier(s) collecté(s)"
say "Analyse"
python src/analyze_logs.py collected "$@"
