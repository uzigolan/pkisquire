"""Compatibility shim.

Enterprise LDAP implementation lives under ``enterprise.ldap_utils``.
"""

try:
    from enterprise.ldap_utils import *  # noqa: F401,F403
except Exception:
    def ldap_authenticate(*args, **kwargs):
        return None

    def ldap_user_exists(*args, **kwargs):
        return False
