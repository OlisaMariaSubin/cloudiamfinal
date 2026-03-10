"""
IAM Over-Permission Detection Engine
"""

import pandas as pd
from collections import defaultdict


# ─────────────────────────────────────────────
# SERVICE ACCOUNT FILTER
# ─────────────────────────────────────────────

SERVICE_PREFIXES = [
    "awsservicerole",
    "awsinternal",
    "cloudtrail",
    "lambda",
    "ecs",
    "eks"
]

SERVICE_KEYWORDS = [
    "service-role",
    "automation",
    "pipeline",
    "deployment",
    "ci-cd"
]


def is_service_account(user):

    if not user:
        return True

    u = str(user).lower()

    for p in SERVICE_PREFIXES:
        if u.startswith(p):
            return True

    for k in SERVICE_KEYWORDS:
        if k in u:
            return True

    return False


# ─────────────────────────────────────────────
# SEVERITY MODEL
# ─────────────────────────────────────────────

RISK_WEIGHTS = {
    "iam:createuser": "Critical",
    "iam:attachuserpolicy": "Critical",
    "iam:passrole": "Critical",
    "ec2:terminateinstances": "Critical",
    "rds:deletedbinstance": "Critical",
    "s3:deletebucket": "Critical",

    "iam:listusers": "High",
    "iam:listroles": "High",

    "s3:putobject": "Medium",
    "lambda:createfunction": "Medium",

    "s3:listbucket": "Low",
    "s3:getobject": "Low"
}

SEVERITY_ORDER = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1
}

WEIGHTS_SCORE = {
    "Critical": 25,
    "High": 10,
    "Medium": 4,
    "Low": 1
}

SEVERITY_COLORS = {
    "Critical": "#FF4B4B",
    "High": "#FF8C00",
    "Medium": "#FFD700",
    "Low": "#00C49F"
}


def get_severity(action):

    action = action.lower()

    if action in RISK_WEIGHTS:
        return RISK_WEIGHTS[action]

    for k in RISK_WEIGHTS:
        if k.split(":")[1] in action:
            return RISK_WEIGHTS[k]

    return "Low"


# ─────────────────────────────────────────────
# EXTRACT USED PERMISSIONS
# ─────────────────────────────────────────────

def extract_used_permissions(logs_df):

    used = defaultdict(set)

    for _, row in logs_df.iterrows():

        user = row.get("user")

        if is_service_account(user):
            continue

        service = str(row.get("service", "")).lower()
        event = str(row.get("eventName", ""))

        if service and event:

            perm = f"{service}:{event}"

            used[user].add(perm)

    return used


# ─────────────────────────────────────────────
# DETECTION
# ─────────────────────────────────────────────

def detect_overpermissions(logs_df):

    used_perms = extract_used_permissions(logs_df)

    findings = []

    for user, perms in used_perms.items():

        for perm in perms:

            sev = get_severity(perm)

            findings.append({
                "User": user,
                "Permission": perm,
                "Service": perm.split(":")[0],
                "Severity": sev,
                "SeverityScore": SEVERITY_ORDER[sev],
                "FindingType": "Permission Used",
                "Recommendation": "Review if this permission is required"
            })

    df = pd.DataFrame(findings)

    if not df.empty:
        df = df.sort_values(["SeverityScore"], ascending=False)

    return df


# ─────────────────────────────────────────────
# RISK SUMMARY
# ─────────────────────────────────────────────

def compute_risk_summary(findings_df):

    if findings_df.empty:
        return {"Critical":0,"High":0,"Medium":0,"Low":0}

    counts = findings_df["Severity"].value_counts().to_dict()

    return {
        "Critical": counts.get("Critical",0),
        "High": counts.get("High",0),
        "Medium": counts.get("Medium",0),
        "Low": counts.get("Low",0)
    }


# ─────────────────────────────────────────────
# USER RISK SCORE
# ─────────────────────────────────────────────

def compute_user_risk_score(findings_df):

    if findings_df.empty:
        return pd.DataFrame()

    rows = []

    for user, group in findings_df.groupby("User"):

        score = 0

        for _, row in group.iterrows():

            base = WEIGHTS_SCORE.get(row["Severity"], 1)

            score += base

        score = min(score, 100)

        rows.append({
            "User": user,
            "RiskScore": score,
            "RiskLevel":
                "Critical" if score >= 60
                else "High" if score >= 30
                else "Medium" if score >= 10
                else "Low",
            "TotalFindings": len(group)
        })

    return pd.DataFrame(rows).sort_values("RiskScore", ascending=False)


# ─────────────────────────────────────────────
# POLICY RECOMMENDATION
# ─────────────────────────────────────────────

def generate_least_privilege_policies(logs_df):

    used = extract_used_permissions(logs_df)

    policies = {}

    for user, perms in used.items():

        policies[user] = {
            "recommended": {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": sorted(list(perms)),
                    "Resource": "*"
                }]
            },
            "meta": {
                "User": user,
                "RecommendedPermissions": len(perms)
            }
        }

    return policies


# ─────────────────────────────────────────────
# USER SUMMARY
# ─────────────────────────────────────────────

def get_persona_summary(logs_df):

    rows = []

    for user, group in logs_df.groupby("user"):

        if is_service_account(user):
            continue

        rows.append({
            "User": user,
            "Actions": len(group),
            "Services": group["service"].nunique(),
            "UniqueActions": group["eventName"].nunique()
        })

    return pd.DataFrame(rows)