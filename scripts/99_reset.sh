#!/usr/bin/env bash
# 99_reset.sh - Remet à zéro les sorties locales (n'arrête pas Docker).
rm -rf collected reports/findings.* reports/analysis_report.md data/localstack_requests
echo "Sorties locales supprimées. Pour réinitialiser LocalStack : (hôte) docker compose down -v"
