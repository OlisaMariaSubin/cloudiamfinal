"""
IAM Over-Permission Detection Engine
Detects over-permissions and unauthorized actions from real CloudTrail logs.

Policy model:
  LegitimatePermissions  — what the role genuinely needs to do its job
  GrantedPermissions     — what AWS actually gave them (legit + over-permissions)
  OverPermissions        — permissions granted but should never have been given
"""

import pandas as pd
from collections import defaultdict


# ── IAM Policies per persona ─────────────────────────────────────────────────
# LegitimatePermissions = what the role should have
# GrantedPermissions    = legit + the dangerous extras they were wrongly given
# OverPermissions       = the dangerous extras (always flagged)

REAL_IAM_POLICIES = {
    'olisa-dev': {
        'Role': 'Developer',
        # What a developer legitimately needs
        'LegitimatePermissions': [
            's3:ListBucket', 's3:PutObject', 's3:GetObject',
            'lambda:ListFunctions', 'lambda:CreateFunction',
            'cloudwatch:DescribeAlarms', 'cloudwatch:GetMetricStatistics', 'cloudwatch:ListMetrics',
            'logs:DescribeLogGroups',
            'ec2:DescribeInstances', 'ec2:DescribeSecurityGroups',
        ],
        # Over-permissions wrongly granted — developer should NEVER have these
        'OverPermissions': [
            'iam:ListUsers', 'iam:ListRoles', 'iam:CreateUser',
            'rds:DescribeDBInstances', 'rds:DescribeDBSnapshots', 'rds:DeleteDBInstance',
            'ec2:TerminateInstances',
        ],
    },
    'joseph-ops': {
        'Role': 'Operations',
        'LegitimatePermissions': [
            'ec2:DescribeInstances', 'ec2:DescribeSecurityGroups', 'ec2:DescribeVpcs',
            'ec2:DescribeSubnets', 'ec2:DescribeKeyPairs', 'ec2:CreateSecurityGroup',
            'rds:DescribeDBInstances', 'rds:DescribeDBSnapshots',
            'cloudwatch:DescribeAlarms', 'cloudwatch:GetMetricStatistics', 'cloudwatch:ListMetrics',
            'cloudwatch:PutMetricAlarm', 'logs:DescribeLogGroups',
        ],
        # Ops should NOT be touching IAM or deleting production resources
        'OverPermissions': [
            'iam:ListUsers', 'iam:ListAttachedUserPolicies', 'iam:AttachUserPolicy',
            'lambda:DeleteFunction', 's3:DeleteBucket',
        ],
    },
    'nayan-analyst': {
        'Role': 'Analyst (Read-Only)',
        # Analyst should only READ — CloudWatch, S3 read, RDS describe
        'LegitimatePermissions': [
            's3:ListBucket', 's3:GetObject',
            'rds:DescribeDBInstances', 'rds:DescribeDBSnapshots',
            'cloudwatch:ListMetrics', 'cloudwatch:GetMetricStatistics', 'cloudwatch:DescribeAlarms',
        ],
        # Everything else is an over-permission for a read-only analyst
        'OverPermissions': [
            's3:PutObject', 's3:DeleteBucket',
            'iam:ListUsers', 'iam:ListRoles', 'iam:CreateUser',
            'ec2:TerminateInstances', 'lambda:DeleteFunction',
        ],
    },
    'jeslin-deployment': {
        'Role': 'CI/CD Deployment',
        # CI/CD needs to deploy Lambdas and upload build artifacts
        'LegitimatePermissions': [
            'lambda:ListFunctions', 'lambda:CreateFunction',
            's3:ListBucket', 's3:PutObject', 's3:GetObject',
            'ec2:DescribeInstances', 'ec2:DescribeSecurityGroups',
            'cloudwatch:DescribeAlarms',
        ],
        # CI/CD should NEVER create IAM users, delete DBs, or terminate infrastructure
        'OverPermissions': [
            'iam:CreateUser', 'iam:AttachUserPolicy',
            'rds:DeleteDBInstance', 'ec2:TerminateInstances', 's3:DeleteBucket',
        ],
    },
    'danil-admin': {
        'Role': 'Admin',
        # Admin legitimately manages IAM, audits, S3, EC2, monitoring
        'LegitimatePermissions': [
            'iam:ListUsers', 'iam:ListRoles', 'iam:GetAccountSummary',
            'iam:GenerateCredentialReport', 'iam:ListAttachedUserPolicies',
            'iam:ListAccessKeys', 'iam:CreateUser', 'iam:AttachUserPolicy',
            'iam:ListPolicies', 'iam:ListAccountAliases',
            's3:ListBucket', 's3:CreateBucket',
            'ec2:DescribeInstances', 'ec2:DescribeSecurityGroups',
            'cloudwatch:DescribeAlarms', 'logs:DescribeLogGroups',
        ],
        # Even admin should not have free-fire destructive permissions
        'OverPermissions': [
            'rds:DeleteDBInstance', 'lambda:DeleteFunction', 'ec2:TerminateInstances',
        ],
    },
}

# Build full GrantedPermissions = legit + over for each user
for _user, _pol in REAL_IAM_POLICIES.items():
    _pol['GrantedPermissions'] = _pol['LegitimatePermissions'] + _pol['OverPermissions']

# ── Severity weights ─────────────────────────────────────────────────────────
# These reflect how dangerous it is for a role to have (and use) this permission

RISK_WEIGHTS = {
    # Critical — identity takeover / privilege escalation / data destruction
    'iam:CreateUser':               'Critical',
    'iam:AttachUserPolicy':         'Critical',
    'iam:DeleteUser':               'Critical',
    'iam:CreateRole':               'Critical',
    'iam:DeleteRole':               'Critical',
    'iam:CreatePolicy':             'Critical',
    'iam:PassRole':                 'Critical',
    'rds:DeleteDBInstance':         'Critical',
    'ec2:TerminateInstances':       'Critical',
    's3:DeleteBucket':              'Critical',

    # High — reconnaissance of identity plane or destructive infra actions
    'iam:ListUsers':                'High',
    'iam:ListRoles':                'High',
    'iam:ListAttachedUserPolicies': 'High',
    'lambda:DeleteFunction':        'High',
    'ec2:RunInstances':             'High',
    'rds:CreateDBInstance':         'High',

    # Medium — write access beyond role scope
    's3:PutObject':                 'Medium',
    'ec2:CreateSecurityGroup':      'Medium',
    'lambda:CreateFunction':        'Medium',
    'rds:DescribeDBInstances':      'Medium',
    'rds:DescribeDBSnapshots':      'Medium',

    # Low — read-only or monitoring
    's3:ListBucket':                'Low',
    's3:GetObject':                 'Low',
    'ec2:DescribeInstances':        'Low',
    'cloudwatch:DescribeAlarms':    'Low',
    'logs:DescribeLogGroups':       'Low',
}

SEVERITY_ORDER  = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}
SEVERITY_COLORS = {'Critical': '#FF4B4B', 'High': '#FF8C00', 'Medium': '#FFD700', 'Low': '#00C49F'}

WEIGHTS_SCORE = {'Critical': 25, 'High': 10, 'Medium': 4, 'Low': 1}


def get_severity(action):
    return RISK_WEIGHTS.get(action, 'Low')


# ── Build permission key from log eventName + service ────────────────────────

def event_to_permission(service, event_name):
    return f"{service}:{event_name}"


# ── Extract actually-used permissions from logs ──────────────────────────────

def extract_used_permissions(logs_df):
    """Return dict: user → set of IAM permission strings used (all attempts, success or fail)."""
    used = defaultdict(set)
    for _, row in logs_df.iterrows():
        user    = row.get('user', 'unknown')
        service = row.get('service', '').lower()
        event   = row.get('eventName', '')
        if user and service and event:
            used[user].add(f"{service}:{event}")
    return used


# ── Main detection — THREE finding types ─────────────────────────────────────

def detect_overpermissions(logs_df, iam_policies=None):
    """
    Three-layer detection:
      1. Over-Permissions Never Used     — granted but never attempted (pure dead weight)
      2. Over-Permissions Actively Used  — user attempted to exercise their over-permissions (active misuse)
      3. Unauthorized Actions            — user attempted actions NOT in their granted list at all
    Returns a combined findings DataFrame with a FindingType column.
    """
    if iam_policies is None:
        iam_policies = REAL_IAM_POLICIES

    used_perms = extract_used_permissions(logs_df)
    findings   = []

    for user, policy in iam_policies.items():
        granted     = set(policy['GrantedPermissions'])
        legit       = set(policy['LegitimatePermissions'])
        over_perms  = set(policy['OverPermissions'])
        used        = used_perms.get(user, set())

        # ── 1. Over-permissions that were never even attempted ────────────────
        over_unused = over_perms - used
        for action in over_unused:
            severity = get_severity(action)
            findings.append({
                'User':             user,
                'Role':             policy['Role'],
                'Permission':       action,
                'Service':          action.split(':')[0].upper(),
                'Severity':         severity,
                'SeverityScore':    SEVERITY_ORDER[severity],
                'FindingType':      'Over-Permission (Unused)',
                'Recommendation':   f"Revoke '{action}' — granted but never used",
            })

        # ── 2. Over-permissions that the user actively tried to use ───────────
        over_used = over_perms & used
        for action in over_used:
            severity = get_severity(action)
            # Bump severity one level — actively using an over-permission is worse
            bumped = {4: 'Critical', 3: 'Critical', 2: 'High', 1: 'Medium'}
            effective_severity = bumped.get(SEVERITY_ORDER[severity], severity)
            findings.append({
                'User':             user,
                'Role':             policy['Role'],
                'Permission':       action,
                'Service':          action.split(':')[0].upper(),
                'Severity':         effective_severity,
                'SeverityScore':    SEVERITY_ORDER[effective_severity],
                'FindingType':      'Over-Permission (Actively Used) ⚠️',
                'Recommendation':   f"URGENT: Revoke '{action}' — user is actively exploiting this",
            })

        # ── 3. Actions attempted that weren't even granted ────────────────────
        unauthorized = used - granted
        for action in unauthorized:
            severity = get_severity(action)
            findings.append({
                'User':             user,
                'Role':             policy['Role'],
                'Permission':       action,
                'Service':          action.split(':')[0].upper(),
                'Severity':         severity,
                'SeverityScore':    SEVERITY_ORDER[severity],
                'FindingType':      'Unauthorized Action 🚨',
                'Recommendation':   f"INVESTIGATE: '{action}' attempted but not in policy",
            })

    df = pd.DataFrame(findings)
    if not df.empty:
        df = df.sort_values(['SeverityScore', 'User'], ascending=[False, True])
    return df


def compute_risk_summary(findings_df):
    if findings_df.empty:
        return {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
    counts = findings_df['Severity'].value_counts().to_dict()
    return {s: counts.get(s, 0) for s in ['Critical', 'High', 'Medium', 'Low']}


def compute_user_risk_score(findings_df):
    """
    Risk score per user. Actively-used over-permissions count double.
    Capped at 100.
    """
    if findings_df.empty:
        return pd.DataFrame()

    rows = []
    for user, group in findings_df.groupby('User'):
        score = 0
        for _, row in group.iterrows():
            base = WEIGHTS_SCORE.get(row['Severity'], 1)
            # Double weight for active exploitation
            multiplier = 2 if 'Actively Used' in row['FindingType'] else 1
            score += base * multiplier
        score = min(score, 100)

        # Determine dominant finding type for label
        has_active   = any('Actively Used' in ft for ft in group['FindingType'])
        has_unauth   = any('Unauthorized'  in ft for ft in group['FindingType'])
        threat_label = '🚨 Active Misuse' if has_active or has_unauth else '⚠️ Over-Permissioned'

        rows.append({
            'User':                   user,
            'RiskScore':              score,
            'RiskLevel':              'Critical' if score >= 60 else 'High' if score >= 30 else 'Medium' if score >= 10 else 'Low',
            'TotalFindings':          len(group),
            'ActiveMisuse':           int(group['FindingType'].str.contains('Actively Used').sum()),
            'UnauthorizedActions':    int(group['FindingType'].str.contains('Unauthorized').sum()),
            'ThreatLabel':            threat_label,
        })
    return pd.DataFrame(rows).sort_values('RiskScore', ascending=False)


def generate_least_privilege_policies(logs_df, iam_policies=None):
    """Generate recommended policies using only the legitimate permissions."""
    if iam_policies is None:
        iam_policies = REAL_IAM_POLICIES

    used_perms = extract_used_permissions(logs_df)
    policies   = {}

    for user, policy in iam_policies.items():
        legit    = sorted(policy['LegitimatePermissions'])
        granted  = sorted(policy['GrantedPermissions'])
        used     = sorted(used_perms.get(user, set()))
        # Recommended = only legit permissions actually used
        legit_used = sorted(set(legit) & set(used)) or legit
        orig_n     = len(granted)
        new_n      = len(legit_used)
        removed    = orig_n - new_n

        policies[user] = {
            'original': {
                'Version': '2012-10-17',
                'Statement': [{'Sid': 'CurrentOverPermissionedPolicy', 'Effect': 'Allow', 'Action': granted, 'Resource': '*'}]
            },
            'recommended': {
                'Version': '2012-10-17',
                'Statement': [{'Sid': 'LeastPrivilegePolicy', 'Effect': 'Allow', 'Action': legit_used, 'Resource': '*'}]
            },
            'meta': {
                'User':                   user,
                'Role':                   policy['Role'],
                'OriginalPermissions':    orig_n,
                'RecommendedPermissions': new_n,
                'PermissionsRemoved':     removed,
                'ReductionPercent':       round(removed / orig_n * 100, 1) if orig_n else 0,
                'OverPermissionsRemoved': len(policy['OverPermissions']),
            }
        }
    return policies


def get_persona_summary(logs_df, iam_policies=None):
    if iam_policies is None:
        iam_policies = REAL_IAM_POLICIES

    used_perms = extract_used_permissions(logs_df)
    rows = []
    for user, policy in iam_policies.items():
        granted   = set(policy['GrantedPermissions'])
        legit     = set(policy['LegitimatePermissions'])
        over      = set(policy['OverPermissions'])
        used      = used_perms.get(user, set())
        over_used = over & used

        rows.append({
            'User':               user,
            'Role':               policy['Role'],
            'Granted':            len(granted),
            'Legitimate':         len(legit),
            'OverPermissions':    len(over),
            'OverPermsUsed':      len(over_used),
            'OverPermRatio%':     round(len(over) / len(granted) * 100, 1) if granted else 0,
        })
    return pd.DataFrame(rows)
