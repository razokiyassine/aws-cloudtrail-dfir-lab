#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
parse_localstack_logs.py - Transforme les logs de requêtes de LocalStack en événements "pseudo-CloudTrail"
==========================================================================================================

CE QUI EST RÉEL : LocalStack écrit dans ses logs une ligne par appel d'API qu'il reçoit, p. ex.
    2026-11-02T14:03:21.512  INFO --- [et.reactor-0] localstack.request.aws : AWS s3.CreateBucket => 200
Ces lignes prouvent que l'appel a VRAIMENT été exécuté dans votre LocalStack.

CE QUI N'EST PAS CLOUDTRAIL : ces lignes ne contiennent NI identité (qui ?), NI adresse IP source,
NI paramètres de la requête. Ce n'est donc PAS un journal CloudTrail. Le script produit des
enregistrements MINIMAUX marqués eventType="LocalStackRequestLog" : seuls l'heure, le service,
l'opération, le code HTTP et l'éventuel code d'erreur sont fiables.

Le format exact des logs peut varier selon la version de LocalStack. Vérifiez avec :
    docker logs lab-localstack 2>&1 | grep "AWS "

Usage (depuis l'hôte) :
    docker logs lab-localstack 2>&1 | docker compose exec -T lab python src/parse_localstack_logs.py -
    # ou, depuis le conteneur lab, avec un fichier :
    python src/parse_localstack_logs.py localstack.log --out data/localstack_requests/localstack_requests.json
"""
import argparse
import json
import re
import sys
import uuid
from pathlib import Path

LINE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?)\S*\s+\w+\s+---\s+\[[^\]]*\]\s+"
    r"localstack\.request\.aws\s*:\s+AWS\s+(?P<svc>[\w\-.]+)\.(?P<op>\w+)\s+=>\s+(?P<status>\d{3})"
    r"(?:\s+\((?P<err>[^)]+)\))?")

SERVICE_TO_SOURCE = {"s3": "s3.amazonaws.com", "iam": "iam.amazonaws.com", "sts": "sts.amazonaws.com",
                     "cloudtrail": "cloudtrail.amazonaws.com"}


def parse(lines):
    recs = []
    for ln in lines:
        m = LINE.match(ln)
        if not m:
            continue
        status = int(m["status"])
        rec = {
            "eventVersion": "lab-localstack-1",
            "userIdentity": {"type": "Unknown"},          # LocalStack ne journalise pas l'identité ici
            "eventTime": m["ts"][:19] + "Z",
            "eventSource": SERVICE_TO_SOURCE.get(m["svc"], f"{m['svc']}.amazonaws.com"),
            "eventName": m["op"],
            "awsRegion": "unknown",
            "sourceIPAddress": "unknown",
            "requestParameters": None,
            "responseElements": {"httpStatus": status},
            "eventID": str(uuid.uuid4()),
            "eventType": "LocalStackRequestLog",           # <- JAMAIS "AwsApiCall" : ce n'est pas CloudTrail
            "managementEvent": True,
            "eventCategory": "Management",
        }
        if status >= 400:
            rec["errorCode"] = m["err"] or f"HTTP{status}"
            rec["errorMessage"] = f"HTTP {status} (log LocalStack)"
        recs.append(rec)
    return recs


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input", help="fichier de logs, ou '-' pour stdin")
    ap.add_argument("--out", default="data/localstack_requests/localstack_requests.json")
    a = ap.parse_args()
    lines = sys.stdin if a.input == "-" else open(a.input, encoding="utf-8", errors="replace")
    recs = parse(lines)
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"_lab_notice": "Derived from LocalStack request logs - NOT CloudTrail.",
                               "Records": recs}, indent=2) + "\n", encoding="utf-8")
    print(f"[OK] {len(recs)} requête(s) LocalStack convertie(s) -> {out}")
    if not recs:
        print("     Aucune ligne reconnue : vérifiez le format avec  docker logs lab-localstack | grep 'AWS '")


if __name__ == "__main__":
    main()
