import boto3


def get_iam_users():

    iam = boto3.client("iam")

    users = []

    paginator = iam.get_paginator("list_users")

    for page in paginator.paginate():

        for u in page["Users"]:
            users.append(u["UserName"])

    return users