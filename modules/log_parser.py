import boto3
import json
import pandas as pd
from datetime import datetime, timedelta

MAX_EVENTS = 2000


def fetch_cloudtrail_events(days=7, username=None):

    cloudtrail = boto3.client("cloudtrail")

    start_time = datetime.utcnow() - timedelta(days=days)
    end_time = datetime.utcnow()

    params = {
        "StartTime": start_time,
        "EndTime": end_time
    }

    if username and username != "All Users":
        params["LookupAttributes"] = [
            {
                "AttributeKey": "Username",
                "AttributeValue": username
            }
        ]

    paginator = cloudtrail.get_paginator("lookup_events")

    events = []

    for page in paginator.paginate(**params):

        for e in page.get("Events", []):

            if len(events) >= MAX_EVENTS:
                return events

            try:
                event = json.loads(e["CloudTrailEvent"])
                events.append(event)
            except Exception:
                continue

    return events


def parse_events(events):

    rows = []

    for r in events:

        identity = r.get("userIdentity", {})

        user = (
            identity.get("userName")
            or identity.get("principalId")
            or identity.get("arn")
            or identity.get("type")
            or "unknown"
        )

        rows.append({
            "eventTime": r.get("eventTime"),
            "user": user,
            "service": r.get("eventSource", "").replace(".amazonaws.com", ""),
            "eventName": r.get("eventName"),
            "awsRegion": r.get("awsRegion"),
            "sourceIPAddress": r.get("sourceIPAddress"),
            "errorCode": r.get("errorCode"),
            "status": "Failed" if r.get("errorCode") else "Success",
            "description": r.get("eventName"),
            "day": pd.to_datetime(r.get("eventTime")).day,
            "isOverPermission": False
        })

    df = pd.DataFrame(rows)

    if not df.empty:
        df["eventTime"] = pd.to_datetime(df["eventTime"], errors="coerce")

    return df


def load_logs(days=7, username=None):

    events = fetch_cloudtrail_events(days, username)

    if not events:
        return pd.DataFrame()

    return parse_events(events)