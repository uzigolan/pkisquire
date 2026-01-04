"""
Lightweight LDAP authentication helper.

This module provides a single function, `ldap_authenticate`, that uses the
connection details from config.ini (passed via app.config) to verify a user's
credentials against the configured LDAP server. It tries a direct bind with
common DN patterns first, then falls back to an admin bind + search if admin
credentials are available.
"""
from typing import Optional, Dict

try:
    from ldap3 import Connection, Server, SUBTREE, ALL
    from ldap3.core.exceptions import LDAPException, LDAPBindError
except ImportError:  # pragma: no cover - handled at runtime
    Connection = None
    Server = None
    SUBTREE = None
    ALL = None

    class LDAPException(Exception):
        """Fallback exception type when ldap3 is unavailable."""

    class LDAPBindError(LDAPException):
        """Fallback bind exception when ldap3 is unavailable."""


def _log(logger, level: str, message: str) -> None:
    """Safe logger helper."""
    if logger:
        log_fn = getattr(logger, level, None)
        if callable(log_fn):
            log_fn(message)


def _build_dn_candidates(username: str, base_dn: Optional[str], people_dn: Optional[str]) -> list[str]:
    """Generate reasonable DN guesses for the user."""
    short = username.split("@", 1)[0] if username and "@" in username else username
    candidates = []
    if people_dn:
        candidates.append(f"uid={username},{people_dn}")
        candidates.append(f"cn={username},{people_dn}")
        if short != username:
            candidates.append(f"uid={short},{people_dn}")
            candidates.append(f"cn={short},{people_dn}")
    if base_dn:
        candidates.append(f"uid={username},{base_dn}")
        candidates.append(f"cn={username},{base_dn}")
        if short != username:
            candidates.append(f"uid={short},{base_dn}")
            candidates.append(f"cn={short},{base_dn}")
    # Deduplicate while preserving order
    seen = set()
    uniq = []
    for dn in candidates:
        if dn not in seen:
            uniq.append(dn)
            seen.add(dn)
    return uniq


def ldap_authenticate(username: str, password: str, cfg: Dict, logger=None) -> Optional[Dict]:
    """
    Attempt to authenticate a user against LDAP.

    Returns a dict with LDAP metadata (e.g., dn, email) on success, or None on failure.
    """
    if not username or not password:
        return None

    if not Connection or not Server:
        _log(logger, "error", "ldap3 is not installed; LDAP authentication is unavailable.")
        return None

    host = cfg.get("LDAP_HOST")
    port = cfg.get("LDAP_PORT", 389)
    base_dn = cfg.get("LDAP_BASE_DN") or cfg.get("BASE_DN")
    people_dn = cfg.get("LDAP_PEOPLE_DN") or cfg.get("PEOPLE_DN")
    admin_dn = cfg.get("LDAP_ADMIN_DN") or cfg.get("ADMIN_DN")
    admin_password = cfg.get("LDAP_ADMIN_PASSWORD") or cfg.get("ADMIN_PASSWORD")
    use_ssl = cfg.get("LDAP_USE_SSL", False)
    if not host:
        return None

    short_username = username.split("@", 1)[0] if "@" in username else username

    server = Server(host, port=port, use_ssl=use_ssl, get_info=ALL)

    # 1) Try direct binds with common DN patterns
    for dn in _build_dn_candidates(username, base_dn, people_dn):
        _log(
            logger,
            "debug",
            f"Attempting user bind with DN: {dn}, host: {host}, port: {port}"
        )
        try:
            conn = Connection(server, user=dn, password=password, auto_bind=True, receive_timeout=5)
            conn.unbind()
            return {"dn": dn}
        except LDAPBindError:
            continue
        except LDAPException as exc:
            _log(logger, "warning", f"LDAP bind attempt failed for {dn}: {exc}")

    # 2) Try admin bind + search if admin credentials are available
    if admin_dn and admin_password and base_dn:
        _log(
            logger,
            "debug",
            f"Attempting admin bind with DN: {admin_dn}, password: {admin_password}, host: {host}, port: {port}"
        )
        try:
            admin_conn = Connection(
                server,
                user=admin_dn,
                password=admin_password,
                auto_bind=True,
                receive_timeout=5,
            )
            # Disable attribute name validation so attributes like sAMAccountName work even if schema is missing
            admin_conn.check_names = False
        except LDAPException as exc:
            _log(logger, "error", f"LDAP admin bind failed: {exc}")
            return None

        search_filter = (
            "(|"
            f"(uid={username})"
            f"(cn={username})"
            f"(mail={username})"
            f"(sAMAccountName={username})"
            f"(uid={short_username})"
            f"(cn={short_username})"
            f"(sAMAccountName={short_username})"
            ")"
        )
        try:
            admin_conn.search(
                search_base=base_dn,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=["mail"],
            )
            entries = admin_conn.entries or []
            if not entries:
                _log(logger, "warning", f"LDAP user {username} not found under {base_dn}.")
                admin_conn.unbind()
                return None

            user_entry = entries[0]
            user_dn = user_entry.entry_dn
            email = None
            try:
                email = user_entry["mail"].value  # type: ignore[index]
            except Exception:
                email = None

            # Log the full LDAP response for the user
            _log(logger, "warning", f"Full LDAP user entry for {username}: {user_entry}")

            try:
                user_conn = Connection(
                    server, user=user_dn, password=password, auto_bind=True, receive_timeout=5
                )
                user_conn.unbind()
                admin_conn.unbind()
                return {"dn": user_dn, "email": email}
            except LDAPBindError:
                _log(logger, "warning", f"LDAP bind failed for discovered DN {user_dn}.")
            except LDAPException as exc:
                _log(logger, "warning", f"LDAP bind error for discovered DN {user_dn}: {exc}")
        finally:
            try:
                admin_conn.unbind()
            except Exception:
                pass

    return None


def ldap_user_exists(username: str, cfg: Dict, logger=None) -> bool:
    """
    Check if a user exists in LDAP using admin bind. No password verification.
    """
    if not username:
        return False
    if not Connection or not Server:
        _log(logger, "error", "ldap3 is not installed; LDAP search unavailable.")
        return False

    host = cfg.get("LDAP_HOST")
    port = cfg.get("LDAP_PORT", 389)
    base_dn = cfg.get("LDAP_BASE_DN") or cfg.get("BASE_DN")
    admin_dn = cfg.get("LDAP_ADMIN_DN") or cfg.get("ADMIN_DN")
    admin_password = cfg.get("LDAP_ADMIN_PASSWORD") or cfg.get("ADMIN_PASSWORD")
    use_ssl = cfg.get("LDAP_USE_SSL", False)
    if not (host and base_dn and admin_dn and admin_password):
        return False

    short_username = username.split("@", 1)[0] if "@" in username else username
    server = Server(host, port=port, use_ssl=use_ssl, get_info=ALL)
    _log(
        logger,
        "debug",
        f"[Exists Check] Attempting admin bind with DN: {admin_dn}, password: {admin_password}, host: {host}, port: {port}"
    )
    try:
        admin_conn = Connection(
            server,
            user=admin_dn,
            password=admin_password,
            auto_bind=True,
            receive_timeout=5,
        )
        admin_conn.check_names = False
    except LDAPException as exc:
        _log(logger, "error", f"LDAP admin bind failed during existence check: {exc}")
        return False

    search_filter = (
        "(|"
        f"(uid={username})"
        f"(cn={username})"
        f"(mail={username})"
        f"(sAMAccountName={username})"
        f"(uid={short_username})"
        f"(cn={short_username})"
        f"(sAMAccountName={short_username})"
        ")"
    )
    try:
        admin_conn.search(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=["dn"],
        )
        entries = admin_conn.entries or []
        return len(entries) > 0
    except LDAPException as exc:
        _log(logger, "warning", f"LDAP search failed during existence check: {exc}")
        return False
    finally:
        try:
            admin_conn.unbind()
        except Exception:
            pass
