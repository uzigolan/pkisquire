# GitHub Copilot Instructions for Pikachu CA

## Rule 1: Certificate Handling
Always use fallback chain: **cryptography library → asn1crypto → OpenSSL CLI**. Never remove OpenSSL CLI fallbacks (required for PQC certificates). Support both PEM and DER formats. Log all operations to `logs/server.log`.

## Rule 2: Configuration & Safety
Never hard-code paths (use `config.ini`). Maintain backward compatibility with existing database. Require DELETE_SECRET for destructive operations. Always add error handling with try/except fallbacks.
