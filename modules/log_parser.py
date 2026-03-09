"""
CloudTrail Log Parser
Reads real JSON log files from the logs/ folder
"""

import pandas as pd
import json
import glob
import os


def parse_log_file(file_path):
    """Parse a single day's CloudTrail JSON log file."""
    with open(file_path, 'r') as f:
        records = json.load(f)

    rows = []
    for r in records:
        user_identity = r.get('userIdentity', {})
        user = user_identity.get('userName', 'unknown') if isinstance(user_identity, dict) else 'unknown'

        rows.append({
            'eventTime':       r.get('eventTime', ''),
            'user':            user,
            'eventSource':     r.get('eventSource', ''),
            'service':         r.get('eventSource', '').replace('.amazonaws.com', ''),
            'eventName':       r.get('eventName', ''),
            'awsRegion':       r.get('awsRegion', ''),
            'sourceIPAddress': r.get('sourceIPAddress', ''),
            'errorCode':       r.get('errorCode'),
            'status':          'Failed' if r.get('errorCode') else 'Success',
            'description':     r.get('description', ''),
            'day':             r.get('day', 0),
            'isOverPermission': r.get('isOverPermission', False),
        })

    df = pd.DataFrame(rows)
    if not df.empty:
        df['eventTime'] = pd.to_datetime(df['eventTime'])
    return df


def load_logs(logs_dir='logs', selected_days=None):
    """
    Load CloudTrail logs from all day*_logs.json files.
    Optionally filter to specific days (list of ints, e.g. [1, 2, 3]).
    """
    all_dfs = []

    pattern = os.path.join(logs_dir, 'day*_logs.json')
    files = sorted(glob.glob(pattern))

    if not files:
        raise FileNotFoundError(f"No log files found in {logs_dir}/")

    for file in files:
        # Extract day number from filename
        basename = os.path.basename(file)
        day_num = int(''.join(filter(str.isdigit, basename.split('_')[0])))

        if selected_days is not None and day_num not in selected_days:
            continue

        df = parse_log_file(file)
        all_dfs.append(df)

    if not all_dfs:
        return pd.DataFrame()

    combined = pd.concat(all_dfs, ignore_index=True)
    combined = combined.sort_values('eventTime').reset_index(drop=True)
    return combined
