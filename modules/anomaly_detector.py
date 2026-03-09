"""
ML-Based Behavioral Anomaly Detector
Uses Isolation Forest on real CloudTrail log features.
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest


def prepare_features(logs_df):
    """Engineer per-user behavioral features from CloudTrail logs."""
    features = []

    for user, group in logs_df.groupby('user'):
        total_actions    = len(group)
        unique_actions   = group['eventName'].nunique()
        unique_services  = group['service'].nunique()
        unique_ips       = group['sourceIPAddress'].nunique()
        failure_count    = (group['status'] == 'Failed').sum()
        failure_rate     = failure_count / total_actions if total_actions > 0 else 0
        overperm_count   = group['isOverPermission'].sum() if 'isOverPermission' in group.columns else 0
        overperm_rate    = overperm_count / total_actions if total_actions > 0 else 0

        iam_actions      = (group['service'] == 'iam').sum()
        iam_ratio        = iam_actions / total_actions if total_actions > 0 else 0

        destructive_kw   = ['Delete', 'Terminate', 'Remove', 'DeleteBucket']
        destructive_count = group['eventName'].apply(
            lambda x: any(kw in str(x) for kw in destructive_kw)
        ).sum()

        features.append({
            'user':             user,
            'total_actions':    total_actions,
            'unique_actions':   unique_actions,
            'unique_services':  unique_services,
            'unique_ips':       unique_ips,
            'failure_count':    int(failure_count),
            'failure_rate':     round(float(failure_rate), 3),
            'iam_ratio':        round(float(iam_ratio), 3),
            'overperm_rate':    round(float(overperm_rate), 3),
            'destructive_count': int(destructive_count),
        })

    return pd.DataFrame(features)


def _explain_anomaly(row):
    reasons = []
    if row['failure_rate'] > 0.08:
        reasons.append(f"High failure rate ({row['failure_rate']*100:.0f}%)")
    if row['iam_ratio'] > 0.05:
        reasons.append(f"Elevated IAM activity ({row['iam_ratio']*100:.0f}%)")
    if row['destructive_count'] > 2:
        reasons.append(f"Multiple destructive actions ({int(row['destructive_count'])})")
    if row['overperm_rate'] > 0.1:
        reasons.append(f"High over-permission usage ({row['overperm_rate']*100:.0f}%)")
    if row['unique_ips'] > 3:
        reasons.append(f"Many source IPs ({int(row['unique_ips'])})")
    return '; '.join(reasons) if reasons else 'Unusual behavior pattern'


def run_anomaly_detection(logs_df):
    """
    Run Isolation Forest anomaly detection on user behavior.
    Returns DataFrame with SuspicionScore, IsAnomaly, AnomalyReason.
    """
    feature_df = prepare_features(logs_df)

    if feature_df.empty or len(feature_df) < 2:
        return pd.DataFrame()

    feature_cols = [
        'total_actions', 'unique_actions', 'unique_services',
        'unique_ips', 'failure_count', 'failure_rate',
        'iam_ratio', 'overperm_rate', 'destructive_count'
    ]

    X = feature_df[feature_cols].values

    model = IsolationForest(n_estimators=100, contamination=0.3, random_state=42)
    model.fit(X)

    predictions = model.predict(X)
    scores      = model.decision_function(X)

    feature_df['AnomalyLabel'] = predictions
    feature_df['AnomalyScore'] = scores
    feature_df['IsAnomaly']    = predictions == -1

    min_s, max_s = scores.min(), scores.max()
    if max_s != min_s:
        feature_df['SuspicionScore'] = ((max_s - scores) / (max_s - min_s) * 100).round(1)
    else:
        feature_df['SuspicionScore'] = 0.0

    feature_df['AnomalyReason'] = feature_df.apply(_explain_anomaly, axis=1)

    return feature_df.sort_values('SuspicionScore', ascending=False)
