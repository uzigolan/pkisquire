"""
Utility functions for OpenSSL operations with optional oqsprovider support.
"""
import subprocess
import functools

# Global cache for provider availability
_OQSPROVIDER_AVAILABLE = None


def check_oqsprovider_available():
    """
    Check if oqsprovider is available in OpenSSL.
    Result is cached after first check.
    """
    global _OQSPROVIDER_AVAILABLE
    
    if _OQSPROVIDER_AVAILABLE is not None:
        return _OQSPROVIDER_AVAILABLE
    
    try:
        # Try to list providers
        result = subprocess.run(
            ["openssl", "list", "-providers"],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        # Check if oqsprovider is in the output
        _OQSPROVIDER_AVAILABLE = "oqsprovider" in result.stdout.lower()
        
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        _OQSPROVIDER_AVAILABLE = False
    
    return _OQSPROVIDER_AVAILABLE


def get_provider_args():
    """
    Get the provider arguments to add to OpenSSL commands if oqsprovider is available.
    Returns a list of arguments to insert into OpenSSL commands.
    """
    if check_oqsprovider_available():
        return ["-provider", "oqsprovider"]
    return []


def build_openssl_command(base_cmd, use_provider=True):
    """
    Build an OpenSSL command with optional provider arguments.
    
    Args:
        base_cmd: List of command arguments (e.g., ["openssl", "x509", "-in", "cert.pem"])
        use_provider: Whether to add provider args if available (default: True)
    
    Returns:
        Complete command list with provider args inserted if available
    """
    if not use_provider or not check_oqsprovider_available():
        return base_cmd
    
    # Insert provider args after "openssl" command
    if len(base_cmd) > 1 and base_cmd[0] == "openssl":
        return [base_cmd[0]] + get_provider_args() + base_cmd[1:]
    
    return base_cmd


def is_pqc_available():
    """
    Check if PQC (Post-Quantum Cryptography) key types are available.
    This is an alias for check_oqsprovider_available() for clearer semantics.
    
    Returns:
        bool: True if PQC algorithms can be used, False otherwise
    """
    return check_oqsprovider_available()


def reset_provider_cache():
    """
    Reset the cached provider availability check.
    Useful for testing or if OpenSSL configuration changes.
    """
    global _OQSPROVIDER_AVAILABLE
    _OQSPROVIDER_AVAILABLE = None
