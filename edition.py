import os


_ENTERPRISE_FEATURES = {
    "est",
    "scep",
    "challenge_passwords",
    "api_tokens",
    "ocsp",
    "ldap",
    "pqc_keys",
}


def get_edition() -> str:
    edition = os.getenv("PIKACHU_EDITION", "community").strip().lower()
    return edition if edition in {"community", "enterprise"} else "community"


def is_enterprise() -> bool:
    return get_edition() == "enterprise"


def feature_enabled(name: str) -> bool:
    if name in _ENTERPRISE_FEATURES:
        return is_enterprise()
    return True
