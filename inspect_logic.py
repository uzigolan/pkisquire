import base64
import os
import subprocess
import tempfile
import time
from cryptography import x509
from cryptography.hazmat.backends import default_backend


def _log_debug(logger, message, *args):
    if logger:
        logger.debug(message, *args)


def _run_command(cmd, logger, text=True, input_data=None, check=False):
    start = time.monotonic()
    proc = subprocess.run(cmd, capture_output=True, text=text, input=input_data, check=check)
    elapsed = time.monotonic() - start
    _log_debug(
        logger,
        "[INSPECT] cmd done rc=%s seconds=%.3f cmd=%s",
        proc.returncode,
        elapsed,
        " ".join(cmd)
    )
    return proc


def _read_file_text(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read().strip()


def run_inspect(
    data,
    der_types,
    convert_public_key_formats,
    convert_private_key_formats,
    build_cert_public_key_formats,
    certificate_to_dict,
    is_pqc_public_key,
    is_ssh2_supported,
    logger=None,
    include_formats=False
):
    formats = None
    if not data:
        _log_debug(logger, "[INSPECT] no data provided")
        return "No data provided.", None

    is_pem = data.startswith("-----BEGIN ")
    _log_debug(logger, "[INSPECT] start len=%s is_pem=%s include_formats=%s", len(data), is_pem, include_formats)

    if not is_pem:
        try:
            der_bytes = base64.b64decode(data)
        except Exception:
            _log_debug(logger, "[INSPECT] base64 decode failed")
            return "Failed to base64-decode input.", None

        fd, path = tempfile.mkstemp(suffix=".der")
        os.close(fd)
        with open(path, "wb") as f:
            f.write(der_bytes)

        detected = None
        detected_cmd = None
        detected_out = None
        failures = []

        for label, subcmd in der_types:
            if label == "Private Key":
                cmd = ["openssl", "pkey", "-inform DER", "-in", path, "-noout", "-text"]
            elif label == "Public Key":
                cmd = ["openssl", "pkey", "-pubin", "-in", path, "-noout", "-text"]
            elif label == "OCSP Request":
                cmd = ["openssl", "ocsp", "-reqin", path, "-text", "-noverify"]
            elif label == "OCSP Response":
                cmd = ["openssl", "ocsp", "-respin", path, "-text", "-noverify"]
            elif label == "PKCS#12 / PFX":
                cmd = ["openssl"] + subcmd + [path]
            else:
                cmd = ["openssl", subcmd[0], "-inform", "DER", "-noout", "-in", path] + subcmd[1:]

            proc = _run_command(cmd, logger, text=True)
            out = proc.stdout.strip() or proc.stderr.strip()

            if proc.returncode == 0:
                detected = label
                detected_cmd = cmd
                detected_out = out
                _log_debug(logger, "[INSPECT] detected der type=%s cmd=%s", detected, " ".join(cmd))
                break
            failures.append((label, cmd, proc.returncode, out))

        if detected:
            header = f"Detected as: {detected}"
            cmd_line = f"$ {' '.join(detected_cmd)}"
            extra_sections = []
            if detected == "Public Key":
                with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as tmp_pem:
                    tmp_pem_path = tmp_pem.name
                try:
                    _run_command(
                        ["openssl", "pkey", "-pubin", "-inform", "DER", "-in", path, "-out", tmp_pem_path],
                        logger,
                        text=True,
                        check=True
                    )
                    if include_formats:
                        pkcs8_pem = _read_file_text(tmp_pem_path)
                        pub_formats = convert_public_key_formats(tmp_pem_path)
                        errors = dict(pub_formats["errors"] or {})
                        if not pkcs8_pem:
                            errors["pkcs8"] = "OpenSSL conversion failed."
                        if pub_formats["openssh"]:
                            extra_sections.append("Converted Public Key (OpenSSH)\n" + pub_formats["openssh"])
                        if pub_formats["rfc4716"]:
                            extra_sections.append("Converted Public Key (RFC4716)\n" + pub_formats["rfc4716"])
                        if not extra_sections and pub_formats["errors"].get("openssh"):
                            extra_sections.append("Public Key format error\n" + pub_formats["errors"]["openssh"])
                        formats = {
                            "kind": "public_key",
                            "pkcs8": pkcs8_pem or None,
                            "openssh": pub_formats["openssh"],
                            "rfc4716": pub_formats["rfc4716"],
                            "errors": errors
                        }
                finally:
                    os.unlink(tmp_pem_path)
            elif detected == "Private Key":
                with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as tmp_pem:
                    tmp_pem_path = tmp_pem.name
                try:
                    _run_command(
                        ["openssl", "pkey", "-inform", "DER", "-in", path, "-out", tmp_pem_path],
                        logger,
                        text=True,
                        check=True
                    )
                    if include_formats:
                        pkcs8_pem = _read_file_text(tmp_pem_path)
                        priv_formats = convert_private_key_formats(tmp_pem_path)
                        errors = dict(priv_formats["errors"] or {})
                        if not pkcs8_pem:
                            errors["pkcs8"] = "OpenSSL conversion failed."
                        if priv_formats["pkcs1"]:
                            extra_sections.append("Converted Private Key (PKCS1)\n" + priv_formats["pkcs1"])
                        if priv_formats["sec1"]:
                            extra_sections.append("Converted Private Key (SEC1)\n" + priv_formats["sec1"])
                        if not extra_sections and priv_formats["errors"].get("private_formats"):
                            extra_sections.append("Private Key format error\n" + priv_formats["errors"]["private_formats"])
                        formats = {
                            "kind": "private_key",
                            "pkcs8": pkcs8_pem or None,
                            "pkcs1": priv_formats["pkcs1"],
                            "sec1": priv_formats["sec1"],
                            "errors": errors
                        }
                finally:
                    os.unlink(tmp_pem_path)
            elif detected == "X.509 Certificate" and include_formats:
                try:
                    cert = x509.load_der_x509_certificate(der_bytes, default_backend())
                    cert_details = certificate_to_dict(cert)
                    pub_formats = build_cert_public_key_formats(cert)
                    formats = {
                        "kind": "certificate",
                        "public_pem": pub_formats["public_pem"],
                        "openssh": pub_formats["openssh"],
                        "rfc4716": pub_formats["rfc4716"],
                        "errors": pub_formats["errors"],
                        "is_pqc_key": is_pqc_public_key(cert_details),
                        "is_ssh2_key": is_ssh2_supported(cert_details)
                    }
                except Exception as e:
                    _log_debug(logger, "[INSPECT] cert parse failed: %s", e)
            os.remove(path)
            return "\n\n".join([header, cmd_line, detected_out] + extra_sections), formats

        lines = ["None of the DER options succeeded. Debug info:"]
        _log_debug(logger, "[INSPECT] no DER type matched, failures=%s", len(failures))
        for lbl, cmd, code, out in failures:
            lines.append(f"--- {lbl} (exit {code}) ---")
            lines.append(f"$ {' '.join(cmd)}")
            lines.append(out or "(no output)")
            lines.append("")
        os.remove(path)
        return "\n".join(lines), None

    fd, path = tempfile.mkstemp(suffix=".pem")
    os.close(fd)
    normalized = data.rstrip() + "\n"
    with open(path, "wb") as f:
        f.write(normalized.encode())

    hdr = data.splitlines()[0].strip()
    _log_debug(logger, "[INSPECT] pem header=%s", hdr)
    if hdr.startswith("-----BEGIN PRIVATE KEY") \
       or hdr.startswith("-----BEGIN RSA PRIVATE KEY") \
       or hdr.startswith("-----BEGIN EC PRIVATE KEY"):
        chosen = "Private Key"
    elif hdr.startswith("-----BEGIN PUBLIC KEY"):
        chosen = "Public Key"
    elif hdr.startswith("-----BEGIN OCSP REQUEST"):
        chosen = "OCSP Request"
    elif hdr.startswith("-----BEGIN OCSP RESPONSE"):
        chosen = "OCSP Response"
    elif hdr.startswith("-----BEGIN CERTIFICATE REQUEST"):
        chosen = "Certificate Signing Request"
    elif hdr.startswith("-----BEGIN CERTIFICATE"):
        chosen = "X.509 Certificate"
    elif hdr.startswith("-----BEGIN X509 CRL") or hdr.startswith("-----BEGIN CRL"):
        chosen = "Certificate Revocation List"
    elif hdr.startswith("-----BEGIN PKCS7") or hdr.startswith("-----BEGIN CMS"):
        chosen = "PKCS#7 / CMS"
    elif hdr.startswith("-----BEGIN PKCS12") or path.lower().endswith((".p12", ".pfx")):
        chosen = "PKCS#12 / PFX"
    else:
        chosen = "X.509 Certificate"

    subcmd = next(cmd for (lbl, cmd) in der_types if lbl == chosen)
    _log_debug(logger, "[INSPECT] chosen=%s", chosen)

    if chosen == "Private Key":
        cmd = ["openssl", "pkey", "-in", path, "-noout", "-text"]
        proc = _run_command(cmd, logger, text=True)
        out, err = proc.stdout, proc.stderr

    elif chosen == "Public Key":
        cmd = ["openssl", "pkey", "-pubin", "-in", path, "-noout", "-text"]
        proc = _run_command(cmd, logger, text=True)
        out, err = proc.stdout, proc.stderr

    elif chosen == "OCSP Response":
        cmd = ["openssl", "ocsp", "-respin", path, "-noout", "-text", "-noverify"]
        proc = _run_command(cmd, logger, text=True)
        out, err = proc.stdout, proc.stderr

    elif chosen == "OCSP Request":
        cmd = ["openssl", "ocsp", "-reqin", path, "-noout", "-text", "-noverify"]
        proc = _run_command(cmd, logger, text=True)
        out, err = proc.stdout, proc.stderr

    elif chosen == "PKCS#12 / PFX":
        cmd = ["openssl", *subcmd, path]
        proc = _run_command(cmd, logger, text=True)
        out, err = proc.stdout, proc.stderr

    else:
        cmd = ["openssl", *subcmd, "-in", path]
        proc = _run_command(cmd, logger, text=True)
        out, err = proc.stdout, proc.stderr

    header = f"Detected: {chosen}"
    cmd_line = f"$ {' '.join(cmd)}"
    body = out.strip() or err.strip()
    extra_sections = []
    if include_formats:
        if chosen == "Public Key":
            pub_formats = convert_public_key_formats(path)
            pkcs8_proc = _run_command(["openssl", "pkey", "-pubin", "-in", path], logger, text=True)
            pkcs8_pem = pkcs8_proc.stdout.strip()
            errors = dict(pub_formats["errors"] or {})
            if pkcs8_proc.returncode != 0 or not pkcs8_pem:
                errors["pkcs8"] = (pkcs8_proc.stderr or "OpenSSL conversion failed.").strip()
            if pub_formats["openssh"]:
                extra_sections.append("Converted Public Key (OpenSSH)\n" + pub_formats["openssh"])
            if pub_formats["rfc4716"]:
                extra_sections.append("Converted Public Key (RFC4716)\n" + pub_formats["rfc4716"])
            if not extra_sections and pub_formats["errors"].get("openssh"):
                extra_sections.append("Public Key format error\n" + pub_formats["errors"]["openssh"])
            formats = {
                "kind": "public_key",
                "pkcs8": pkcs8_pem or data,
                "openssh": pub_formats["openssh"],
                "rfc4716": pub_formats["rfc4716"],
                "errors": errors
            }
        elif chosen == "Private Key":
            priv_formats = convert_private_key_formats(path)
            pkcs8_proc = _run_command(["openssl", "pkey", "-in", path], logger, text=True)
            pkcs8_pem = pkcs8_proc.stdout.strip()
            errors = dict(priv_formats["errors"] or {})
            if pkcs8_proc.returncode != 0 or not pkcs8_pem:
                errors["pkcs8"] = (pkcs8_proc.stderr or "OpenSSL conversion failed.").strip()
            if priv_formats["pkcs1"]:
                extra_sections.append("Converted Private Key (PKCS1)\n" + priv_formats["pkcs1"])
            if priv_formats["sec1"]:
                extra_sections.append("Converted Private Key (SEC1)\n" + priv_formats["sec1"])
            if not extra_sections and priv_formats["errors"].get("private_formats"):
                extra_sections.append("Private Key format error\n" + priv_formats["errors"]["private_formats"])
            formats = {
                "kind": "private_key",
                "pkcs8": pkcs8_pem or data,
                "pkcs1": priv_formats["pkcs1"],
                "sec1": priv_formats["sec1"],
                "errors": errors
            }
        elif chosen == "X.509 Certificate":
            try:
                cert = x509.load_pem_x509_certificate(normalized.encode("utf-8"), default_backend())
                cert_details = certificate_to_dict(cert)
                pub_formats = build_cert_public_key_formats(cert)
                formats = {
                    "kind": "certificate",
                    "public_pem": pub_formats["public_pem"],
                    "openssh": pub_formats["openssh"],
                    "rfc4716": pub_formats["rfc4716"],
                    "errors": pub_formats["errors"],
                    "is_pqc_key": is_pqc_public_key(cert_details),
                    "is_ssh2_key": is_ssh2_supported(cert_details)
                }
            except Exception as e:
                _log_debug(logger, "[INSPECT] cert parse failed: %s", e)
    os.remove(path)
    return "\n\n".join([header, cmd_line, body] + extra_sections), formats
