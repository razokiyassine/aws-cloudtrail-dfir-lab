#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
analyze_logs.py - Analyseur de journaux au format AWS CloudTrail (règles de détection)
======================================================================================

Lit des fichiers .json / .json.gz contenant {"Records": [...]} (vrais journaux CloudTrail
OU événements synthétiques du labo), applique des règles de détection, puis produit :

  reports/analysis_report.md   rapport lisible (chronologie, alertes, recommandations)
  reports/findings.json        alertes au format machine
  reports/findings.csv         alertes au format tableur

Règles implémentées (chaque règle porte une correspondance MITRE ATT&CK) :
  R01  Connexion console réussie sans MFA
  R02  Attribution de privilèges d'administration (AdministratorAccess / Action:* Resource:*)
  R03  Création de clé d'accès pour un AUTRE utilisateur / depuis une IP externe,
       et utilisation d'une clé fraîchement créée depuis une IP externe
  R04  Suppression de bucket S3
  R05  Altération de la journalisation CloudTrail (StopLogging, DeleteTrail, UpdateTrail...)
  R06  Accès refusés (isolés = LOW ; rafale >= 3 en 10 min = HIGH)
  R07  Échecs de connexion console répétés (>= 3 en 10 min), CRITICAL si suivis d'un succès
  R08  Trou de journalisation (aucun événement pendant > N minutes)
  R09  Activité d'un principal IAM depuis une IP hors plages de l'entreprise

Bibliothèque standard uniquement (Python >= 3.9).

Usage :
  python src/analyze_logs.py                       # analyse data/s3_layout
  python src/analyze_logs.py collected/ --gap-minutes 20
  python src/analyze_logs.py data/dataset_full.json --corp-cidrs 198.51.100.0/24,10.0.0.0/8
"""
from __future__ import annotations

import argparse
import csv
import gzip
import ipaddress
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

SEV = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
SEV_NAMES = {v: k for k, v in SEV.items()}
DEFAULT_CORP_CIDRS = "198.51.100.0/24,10.0.0.0/8"
ACCESS_DENIED_CODES = {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation",
                       "Client.UnauthorizedOperation", "UnauthorizedAccess", "AuthFailure"}
TRAIL_TAMPERING = {"StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors",
                   "PutInsightSelectors", "RemoveTags"}
SENSITIVE_BUCKET = re.compile(r"(prod|backup|finance|secret|payroll|log|audit)", re.I)

# Métadonnées par règle : titre, MITRE ATT&CK, mesures correctives
RULES = {
    "R01": ("Connexion console sans MFA", "T1078.004 Valid Accounts: Cloud Accounts",
            "Imposer le MFA à tous les utilisateurs IAM (politique deny-sans-MFA), réinitialiser le mot de passe "
            "du compte, révoquer les sessions actives, privilégier IAM Identity Center."),
    "R02": ("Attribution de privilèges administrateur", "T1098.003 Account Manipulation: Additional Cloud Roles",
            "Détacher la politique, retirer iam:AttachUserPolicy aux non-administrateurs, définir une permissions "
            "boundary / SCP interdisant l'auto-élévation, alerter en temps réel (EventBridge)."),
    "R03": ("Clé d'accès non autorisée / usage suspect", "T1098.001 Account Manipulation: Additional Cloud Credentials",
            "Désactiver puis supprimer la clé, auditer toutes les actions faites avec, limiter iam:CreateAccessKey "
            "(Condition aws:username), préférer des rôles/sessions temporaires aux clés longues."),
    "R04": ("Suppression de bucket S3", "T1485 Data Destruction",
            "Activer versioning + MFA Delete + Object Lock sur les buckets critiques, répliquer vers un autre compte, "
            "restreindre s3:DeleteBucket, restaurer depuis la sauvegarde isolée."),
    "R05": ("Altération de la journalisation CloudTrail", "T1562.008 Impair Defenses: Disable or Modify Cloud Logs",
            "Relancer la trail, protéger cloudtrail:StopLogging/DeleteTrail/UpdateTrail par SCP (Organizations), "
            "trail multi-région + validation d'intégrité des fichiers, copie des logs vers un compte de logs dédié."),
    "R06": ("Accès refusé(s) à des ressources", "T1580 Cloud Infrastructure Discovery / T1087.004 Cloud Account Discovery",
            "Investiguer l'identité source, vérifier la légitimité du besoin, appliquer le moindre privilège, "
            "ajouter une alerte de seuil sur les AccessDenied."),
    "R07": ("Échecs de connexion console répétés", "T1110 Brute Force",
            "Verrouiller/surveiller le compte, imposer MFA, filtrer par IP source, activer des alertes sur "
            "ConsoleLogin=Failure, réinitialiser le mot de passe si succès consécutif."),
    "R08": ("Trou de journalisation", "T1562.008 Impair Defenses: Disable or Modify Cloud Logs",
            "Déterminer la cause (StopLogging ? panne ?), relancer la trail, reconstituer l'activité avec d'autres "
            "sources (S3 server access logs, GuardDuty, VPC Flow Logs, CloudWatch), alarme IsLogging=false."),
    "R09": ("Activité depuis une IP hors périmètre", "T1078.004 Valid Accounts: Cloud Accounts",
            "Vérifier la géolocalisation/ASN, restreindre par condition aws:SourceIp, révoquer les identifiants "
            "concernés, enrichir avec une liste d'IP de confiance."),
}


# --------------------------------------------------------------------------------------
# Chargement
# --------------------------------------------------------------------------------------
def parse_time(s: str) -> datetime:
    s = s.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)


def _read_file(p: Path):
    opener = gzip.open if p.suffix == ".gz" else open
    with opener(p, "rt", encoding="utf-8") as fh:
        return json.load(fh)


def load_records(paths: list[str]) -> tuple[list[dict], dict]:
    """Charge tous les .json/.json.gz (récursif), dédoublonne sur eventID, trie par date."""
    files: list[Path] = []
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            files += [f for f in p.rglob("*") if f.name.endswith((".json", ".json.gz"))]
        elif p.is_file():
            files.append(p)
        else:
            print(f"[WARN] chemin introuvable : {p}", file=sys.stderr)
    seen, records, bad = set(), [], 0
    for f in sorted(files):
        try:
            data = _read_file(f)
        except (OSError, ValueError, EOFError) as exc:
            print(f"[WARN] fichier ignoré {f} : {exc}", file=sys.stderr)
            bad += 1
            continue
        recs = data.get("Records") if isinstance(data, dict) else None
        if not isinstance(recs, list):
            continue            # ex. answer_key.json : pas un journal
        for r in recs:
            eid = r.get("eventID") or f"{f}:{len(records)}"
            if eid in seen:
                continue
            seen.add(eid)
            records.append(r)
    records.sort(key=lambda r: r.get("eventTime", ""))
    return records, {"files": len(files), "bad_files": bad}


# --------------------------------------------------------------------------------------
# Helpers d'extraction
# --------------------------------------------------------------------------------------
def principal(r: dict) -> str:
    ui = r.get("userIdentity") or {}
    if ui.get("userName"):
        return ui["userName"]
    arn = ui.get("arn") or ""
    return arn.split("/")[-2] if "assumed-role" in arn and arn.count("/") >= 2 else (arn.split("/")[-1] or ui.get("type", "?"))


def src_ip(r: dict) -> str:
    return r.get("sourceIPAddress", "?")


def is_external(ip: str, nets) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False            # "cloudtrail.amazonaws.com", "AWS Internal"... -> pas une IP
    return not any(a in n for n in nets)


def params(r: dict) -> dict:
    return r.get("requestParameters") or {}


def mfa_used(r: dict):
    return (r.get("additionalEventData") or {}).get("MFAUsed")


def finding(rule, sev, r, details, *, events=None, ext=False):
    title, mitre, fix = RULES[rule]
    return {"rule": rule, "title": title, "severity": sev, "eventID": r.get("eventID"),
            "eventTime": r.get("eventTime"), "eventName": r.get("eventName"),
            "principal": principal(r), "sourceIP": src_ip(r), "region": r.get("awsRegion"),
            "details": details, "mitre": mitre, "external_ip": ext,
            "related_eventIDs": events or [r.get("eventID")], "recommendation": fix}


def bump(sev: str, n: int = 1) -> str:
    return SEV_NAMES[min(SEV[sev] + n, SEV["CRITICAL"])]


# --------------------------------------------------------------------------------------
# Règles
# --------------------------------------------------------------------------------------
def run_detections(records: list[dict], corp_cidrs: str = DEFAULT_CORP_CIDRS, gap_minutes: int = 30) -> list[dict]:
    nets = [ipaddress.ip_network(c.strip()) for c in corp_cidrs.split(",") if c.strip()]
    F: list[dict] = []
    created_keys: dict[str, dict] = {}     # accessKeyId -> {time, by}

    # --- règles événement par événement ---
    for r in records:
        name, ip = r.get("eventName", ""), src_ip(r)
        ext = is_external(ip, nets)
        err = r.get("errorCode")
        p = params(r)

        # R01
        if name == "ConsoleLogin" and (r.get("responseElements") or {}).get("ConsoleLogin") == "Success" \
                and mfa_used(r) == "No":
            sev = "CRITICAL" if ext else "HIGH"
            F.append(finding("R01", sev, r, f"Connexion réussie de {principal(r)} sans MFA depuis {ip}", ext=ext))

        # R02
        if name in ("AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy"):
            arn = p.get("policyArn", "")
            if arn.endswith("/AdministratorAccess") or arn.endswith(":policy/AdministratorAccess"):
                target = p.get("userName") or p.get("roleName") or p.get("groupName")
                sev = "HIGH" if err else "CRITICAL"
                what = "TENTATIVE refusée" if err else "attribution réussie"
                F.append(finding("R02", sev, r,
                                 f"{principal(r)} -> {name} {arn} sur '{target}' ({what}) depuis {ip}", ext=ext))
        if name in ("PutUserPolicy", "PutRolePolicy", "PutGroupPolicy", "CreatePolicy", "CreatePolicyVersion"):
            doc = p.get("policyDocument", "")
            if isinstance(doc, str) and re.search(r'"Action"\s*:\s*"\*"', doc) and re.search(r'"Resource"\s*:\s*"\*"', doc):
                F.append(finding("R02", "CRITICAL", r, f"Politique Action:* / Resource:* créée par {principal(r)}", ext=ext))

        # R03 : création de clé
        if name == "CreateAccessKey" and not err:
            actor = principal(r)
            target = p.get("userName") or actor
            new_key = ((r.get("responseElements") or {}).get("accessKey") or {}).get("accessKeyId")
            if new_key:
                created_keys[new_key] = {"time": r.get("eventTime"), "by": actor, "target": target}
            if actor != target:
                sev = "CRITICAL" if ext else "HIGH"
                F.append(finding("R03", sev, r, f"{actor} a créé une clé d'accès pour un AUTRE utilisateur '{target}' "
                                                f"(clé {new_key}) depuis {ip}", ext=ext))
            elif ext:
                F.append(finding("R03", "HIGH", r, f"{actor} crée une clé pour lui-même depuis une IP externe {ip}", ext=True))
            else:
                F.append(finding("R03", "INFO", r, f"{actor} crée une clé pour lui-même depuis une IP interne "
                                                   f"(rotation probable : à vérifier)"))

        # R03 : usage d'une clé créée pendant la période d'observation, depuis une IP externe
        ak = (r.get("userIdentity") or {}).get("accessKeyId")
        if ak in created_keys and name != "CreateAccessKey" and ext:
            F.append(finding("R03", "HIGH", r, f"Clé {ak} (créée à {created_keys[ak]['time']} par "
                                               f"{created_keys[ak]['by']}) utilisée depuis l'IP externe {ip} ({name})", ext=True))

        # R04
        if name == "DeleteBucket" and not err:
            bucket = p.get("bucketName", "?")
            sev = "HIGH" if SENSITIVE_BUCKET.search(bucket) else "MEDIUM"
            if ext:
                sev = bump(sev)
            F.append(finding("R04", sev, r, f"{principal(r)} a supprimé le bucket '{bucket}' depuis {ip}", ext=ext))

        # R05
        if r.get("eventSource") == "cloudtrail.amazonaws.com" and name in TRAIL_TAMPERING:
            tr = p.get("name", "?")
            outcome = f"REFUSÉE ({err})" if err else "RÉUSSIE"
            F.append(finding("R05", "CRITICAL", r, f"{principal(r)} : {name} sur {tr} -> tentative {outcome} depuis {ip}", ext=ext))

        # R06 (événement isolé)
        if err in ACCESS_DENIED_CODES:
            F.append(finding("R06", "LOW", r, f"{principal(r)} : {name} refusé ({err}) depuis {ip}", ext=ext))

    # --- R06 rafales : >= 3 refus en 10 min par principal ---
    denied = defaultdict(list)
    for r in records:
        if r.get("errorCode") in ACCESS_DENIED_CODES:
            denied[principal(r)].append(r)
    for who, lst in denied.items():
        i = 0
        while i < len(lst):
            t0 = parse_time(lst[i]["eventTime"])
            win = [x for x in lst[i:] if parse_time(x["eventTime"]) - t0 <= timedelta(minutes=10)]
            if len(win) >= 3:
                ips = sorted({src_ip(x) for x in win})
                ext = any(is_external(x, nets) for x in ips)
                F.append(finding("R06", "CRITICAL" if ext and len(win) >= 4 else "HIGH", win[0],
                                 f"RAFALE : {len(win)} refus en <10 min pour {who} "
                                 f"({', '.join(sorted({x['eventName'] for x in win}))}) depuis {', '.join(ips)}",
                                 events=[x["eventID"] for x in win], ext=ext))
                i += len(win)
            else:
                i += 1

    # --- R07 : échecs de connexion répétés ---
    fails = defaultdict(list)
    succ = defaultdict(list)
    for r in records:
        if r.get("eventName") == "ConsoleLogin":
            outcome = (r.get("responseElements") or {}).get("ConsoleLogin")
            (fails if outcome == "Failure" else succ)[(principal(r), src_ip(r))].append(r)
    for (who, ip), lst in fails.items():
        i = 0
        while i < len(lst):
            t0 = parse_time(lst[i]["eventTime"])
            win = [x for x in lst[i:] if parse_time(x["eventTime"]) - t0 <= timedelta(minutes=10)]
            if len(win) >= 3:
                tlast = parse_time(win[-1]["eventTime"])
                follow = [s for s in succ.get((who, ip), [])
                          if timedelta(0) <= parse_time(s["eventTime"]) - tlast <= timedelta(minutes=15)]
                ext = is_external(ip, nets)
                sev = "CRITICAL" if follow else "HIGH"
                extra = f" puis SUCCÈS à {follow[0]['eventTime']} (compromission probable)" if follow else ""
                F.append(finding("R07", sev, win[0], f"{len(win)} échecs de connexion pour {who} depuis {ip}{extra}",
                                 events=[x["eventID"] for x in win] + [s["eventID"] for s in follow], ext=ext))
                i += len(win)
            else:
                i += 1

    # --- R08 : trou de journalisation ---
    thr = timedelta(minutes=gap_minutes)
    for a, b in zip(records, records[1:]):
        ta, tb = parse_time(a["eventTime"]), parse_time(b["eventTime"])
        if tb - ta > thr:
            minutes = int((tb - ta).total_seconds() // 60)
            stops = [x for x in records if x.get("eventName") == "StopLogging"
                     and timedelta(0) <= parse_time(x["eventTime"]) - ta <= timedelta(minutes=2)]
            if stops:
                s = stops[0]
                F.append(finding("R08", "CRITICAL", s,
                                 f"Aucun événement de {a['eventTime']} à {b['eventTime']} ({minutes} min). Cause probable : "
                                 f"StopLogging par {principal(s)} à {s['eventTime']}, "
                                 f"redémarrage par {principal(b)} ({b.get('eventName')}). "
                                 f"Toute action pendant ce créneau est INVISIBLE dans CloudTrail.",
                                 events=[s["eventID"], b["eventID"]], ext=is_external(src_ip(s), nets)))
            else:
                F.append(finding("R08", "MEDIUM", a,
                                 f"Silence de {minutes} min entre {a['eventTime']} et {b['eventTime']} "
                                 f"(seuil {gap_minutes} min) : cause à investiguer", events=[a["eventID"], b["eventID"]]))

    # --- R09 : IP hors périmètre (agrégé par principal+IP) ---
    agg = defaultdict(list)
    for r in records:
        ip = src_ip(r)
        if (r.get("userIdentity") or {}).get("type") in ("IAMUser", "AssumedRole", "Root") and is_external(ip, nets):
            agg[(principal(r), ip)].append(r)
    for (who, ip), lst in agg.items():
        names = Counter(x["eventName"] for x in lst)
        sev = "HIGH" if len(lst) >= 10 else "MEDIUM"
        F.append(finding("R09", sev, lst[0],
                         f"{len(lst)} événement(s) de {who} depuis l'IP hors périmètre {ip} "
                         f"({lst[0]['eventTime']} -> {lst[-1]['eventTime']}) : "
                         + ", ".join(f"{n}x{c}" for n, c in names.most_common(6)),
                         events=[x["eventID"] for x in lst], ext=True))

    F.sort(key=lambda f: (-SEV[f["severity"]], f["eventTime"], f["rule"]))
    return F


# --------------------------------------------------------------------------------------
# Rapport
# --------------------------------------------------------------------------------------
def build_report(records, findings, meta, args) -> str:
    L = []
    t0 = records[0]["eventTime"] if records else "-"
    t1 = records[-1]["eventTime"] if records else "-"
    L += ["# Rapport d'analyse automatique de journaux de type CloudTrail", "",
          "> **Avertissement** : si l'entrée est `data/s3_layout` ou `data/dataset_*.json`, ces événements sont "
          "**synthétiques** (générés par `generate_events.py`). Ils ne proviennent pas d'un vrai CloudTrail.", "",
          "## 1. Périmètre", "",
          f"- Fichiers lus : {meta['files']} (illisibles : {meta['bad_files']})",
          f"- Événements uniques analysés : **{len(records)}**",
          f"- Période couverte : {t0} -> {t1}",
          f"- Plages IP de confiance : `{args.corp_cidrs}` | seuil de silence : {args.gap_minutes} min", ""]

    by_sev = Counter(f["severity"] for f in findings)
    L += ["## 2. Synthèse des alertes", "", "| Sévérité | Nombre |", "|---|---|"]
    for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        L.append(f"| {s} | {by_sev.get(s, 0)} |")
    L.append("")
    by_rule = Counter(f["rule"] for f in findings)
    L += ["| Règle | Titre | Alertes | MITRE ATT&CK |", "|---|---|---|---|"]
    for rid, (title, mitre, _) in RULES.items():
        L.append(f"| {rid} | {title} | {by_rule.get(rid, 0)} | {mitre} |")
    L.append("")

    L += ["## 3. Alertes de sévérité MEDIUM ou plus", ""]
    for f in [x for x in findings if SEV[x["severity"]] >= SEV["MEDIUM"]]:
        L += [f"### [{f['severity']}] {f['rule']} - {f['title']}",
              f"- **Quand** : {f['eventTime']} | **Qui** : `{f['principal']}` | **IP** : `{f['sourceIP']}` | **Événement** : `{f['eventName']}`",
              f"- **Détail** : {f['details']}",
              f"- **eventID(s)** : {', '.join(f['related_eventIDs'][:6])}{' ...' if len(f['related_eventIDs']) > 6 else ''}", ""]

    low = [x for x in findings if SEV[x["severity"]] <= SEV["LOW"]]
    L += ["## 4. Alertes LOW / INFO (à trier - candidats faux positifs)", ""]
    if low:
        L += ["| Sév. | Règle | Heure | Principal | Détail |", "|---|---|---|---|---|"]
        for f in low:
            L.append(f"| {f['severity']} | {f['rule']} | {f['eventTime']} | {f['principal']} | {f['details']} |")
    else:
        L.append("Aucune.")
    L.append("")

    # Chronologie : tous les événements des IP externes impliquées dans une alerte >= HIGH
    bad_ips = sorted({f["sourceIP"] for f in findings if SEV[f["severity"]] >= SEV["HIGH"] and f["external_ip"]})
    L += ["## 5. Chronologie de l'incident (activité des IP externes suspectes)", ""]
    if bad_ips:
        L.append(f"IP suspectes : {', '.join('`'+i+'`' for i in bad_ips)}")
        L += ["", "| Heure (UTC) | Principal | Événement | Résultat | IP |", "|---|---|---|---|---|"]
        for r in records:
            if src_ip(r) in bad_ips:
                res = r.get("errorCode") or (r.get("responseElements") or {}).get("ConsoleLogin") or "OK"
                L.append(f"| {r['eventTime']} | {principal(r)} | {r['eventName']} | {res} | {src_ip(r)} |")
    else:
        L.append("Aucune IP externe associée à une alerte HIGH/CRITICAL.")
    L.append("")

    gaps = [f for f in findings if f["rule"] == "R08"]
    L += ["## 6. Fenêtres de journalisation interrompue", ""]
    L += ([f"- [{g['severity']}] {g['details']}" for g in gaps] if gaps else ["Aucun trou détecté."])
    L.append("")

    L += ["## 7. Mesures correctives recommandées (par règle déclenchée)", ""]
    for rid in sorted({f["rule"] for f in findings if SEV[f["severity"]] >= SEV["MEDIUM"]}):
        L.append(f"- **{rid} - {RULES[rid][0]}** : {RULES[rid][2]}")
    L += ["", "## 8. Limites de l'analyse", "",
          "- Règles à seuils fixes : elles n'identifient pas tout et génèrent des faux positifs (cf. section 4).",
          "- Un attaquant qui coupe la journalisation rend ses actions invisibles : croiser avec d'autres sources.",
          "- Les événements de données S3 n'existent que si les *data events* sont activés sur la trail.",
          "- Les verdicts sont des **hypothèses d'investigation**, à confirmer auprès des personnes concernées.", ""]
    return "\n".join(L)


def write_outputs(records, findings, meta, args) -> Path:
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "analysis_report.md").write_text(build_report(records, findings, meta, args), encoding="utf-8")
    (out / "findings.json").write_text(json.dumps(findings, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    with open(out / "findings.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["severity", "rule", "eventTime", "principal", "sourceIP", "eventName", "details", "mitre", "eventID"])
        for f in findings:
            w.writerow([f["severity"], f["rule"], f["eventTime"], f["principal"], f["sourceIP"],
                        f["eventName"], f["details"], f["mitre"], f["eventID"]])
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Analyse de journaux au format CloudTrail.")
    ap.add_argument("paths", nargs="*", default=["data/s3_layout"], help="fichiers ou dossiers (.json/.json.gz)")
    ap.add_argument("--corp-cidrs", default=DEFAULT_CORP_CIDRS, help="plages IP de confiance, séparées par des virgules")
    ap.add_argument("--gap-minutes", type=int, default=30, help="seuil de silence pour R08 (défaut 30)")
    ap.add_argument("--out-dir", default="reports", help="dossier de sortie")
    ap.add_argument("--min-severity", default="MEDIUM", choices=list(SEV), help="sévérité minimale affichée en console")
    args = ap.parse_args()

    records, meta = load_records(args.paths)
    if not records:
        print("[ERREUR] Aucun enregistrement trouvé. Avez-vous lancé generate_events.py / synchronisé S3 ?", file=sys.stderr)
        return 2
    findings = run_detections(records, args.corp_cidrs, args.gap_minutes)
    out = write_outputs(records, findings, meta, args)

    print(f"Événements analysés : {len(records)} ({meta['files']} fichiers)")
    print(f"Alertes : " + ", ".join(f"{s}={sum(1 for f in findings if f['severity']==s)}" for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")))
    print("-" * 100)
    for f in findings:
        if SEV[f["severity"]] >= SEV[args.min_severity]:
            print(f"[{f['severity']:<8}] {f['rule']} {f['eventTime']}  {f['principal']:<11} {f['details'][:110]}")
    print("-" * 100)
    print(f"Rapport : {out/'analysis_report.md'} | {out/'findings.json'} | {out/'findings.csv'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
