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


def filter_human_users(users):

    return [u for u in users if not is_service_account(u)]