import argparse
import configparser
import sys
import subprocess
import tempfile
from pathlib import Path

from openssl_utils import build_openssl_command


def load_ini(path):
    parser = configparser.ConfigParser(interpolation=None)
    with open(path, "r", encoding="utf-8") as handle:
        parser.read_file(handle)
    return parser


def get_required(parser, section, option):
    if not parser.has_option(section, option):
        raise KeyError(f"Missing [{section}] {option}")
    return parser.get(section, option)


def get_bool(parser, section, option, default=False):
    if not parser.has_option(section, option):
        return default
    return parser.getboolean(section, option)


def resolve_path(value):
    path = Path(value)
    if path.is_absolute():
        return path
    return Path.cwd() / path


def ensure_parent(path):
    path.parent.mkdir(parents=True, exist_ok=True)


def run_openssl(args):
    cmd = build_openssl_command(args, use_provider=False)
    subprocess.run(cmd, check=True)


def write_chain(chain_path, subca_cert_path, root_cert_path):
    sub_bytes = subca_cert_path.read_bytes()
    root_bytes = root_cert_path.read_bytes()
    if not sub_bytes.endswith(b"\n"):
        sub_bytes += b"\n"
    chain_path.write_bytes(sub_bytes + root_bytes)


def main():
    parser = argparse.ArgumentParser(
        description="Generate root CA and sub-CA keys/certs based on ca_pki.ini and config.ini."
    )
    parser.add_argument(
        "--config",
        default="config.ini",
        help="Path to config.ini (default: config.ini).",
    )
    parser.add_argument(
        "--pki-config",
        default="ca_pki.ini",
        help="Path to ca_pki.ini (default: ca_pki.ini).",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing keys/certs if they already exist.",
    )
    args = parser.parse_args()

    config_path = resolve_path(args.config)
    pki_config_path = resolve_path(args.pki_config)

    if not config_path.exists():
        print(f"ERROR: config not found: {config_path}", file=sys.stderr)
        return 1
    if not pki_config_path.exists():
        print(f"ERROR: PKI config not found: {pki_config_path}", file=sys.stderr)
        return 1

    app_cfg = load_ini(config_path)
    pki_cfg = load_ini(pki_config_path)

    try:
        ca_section = "CA"
        subca_key_path_ec = resolve_path(get_required(app_cfg, ca_section, "subca_key_path_ec"))
        subca_cert_path_ec = resolve_path(get_required(app_cfg, ca_section, "subca_cert_path_ec"))
        chain_file_path_ec = resolve_path(get_required(app_cfg, ca_section, "chain_file_path_ec"))
        subca_key_path_rsa = resolve_path(get_required(app_cfg, ca_section, "subca_key_path_rsa"))
        subca_cert_path_rsa = resolve_path(get_required(app_cfg, ca_section, "subca_cert_path_rsa"))
        chain_file_path_rsa = resolve_path(get_required(app_cfg, ca_section, "chain_file_path_rsa"))
        root_cert_path = resolve_path(get_required(app_cfg, ca_section, "root_cert_path"))
    except KeyError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    root_key_path_value = pki_cfg.get("OUTPUT", "root_key_path", fallback="").strip()
    if root_key_path_value:
        root_key_path = resolve_path(root_key_path_value)
    else:
        root_key_path = root_cert_path.with_suffix(".key")

    outputs = [
        root_key_path,
        root_cert_path,
        subca_key_path_ec,
        subca_cert_path_ec,
        chain_file_path_ec,
        subca_key_path_rsa,
        subca_cert_path_rsa,
        chain_file_path_rsa,
    ]

    existing = [path for path in outputs if path.exists()]
    if existing and not args.force:
        print("Output files already exist:")
        for path in existing:
            print(f"  - {path}")
        if not sys.stdin.isatty():
            print("ERROR: Non-interactive input; aborting. Use --force to overwrite.", file=sys.stderr)
            return 1
        answer = input("Overwrite these files? [y/N]: ").strip().lower()
        if answer not in ("y", "yes"):
            print("Aborted.")
            return 1

    if existing:
        for path in existing:
            path.unlink()

    ensure_parent(root_key_path)
    ensure_parent(root_cert_path)
    ensure_parent(subca_key_path_ec)
    ensure_parent(subca_cert_path_ec)
    ensure_parent(chain_file_path_ec)
    ensure_parent(subca_key_path_rsa)
    ensure_parent(subca_cert_path_rsa)
    ensure_parent(chain_file_path_rsa)

    root_days = pki_cfg.getint("ROOT", "days", fallback=3650)
    root_md = pki_cfg.get("ROOT", "default_md", fallback="sha256")
    root_key_type = pki_cfg.get("ROOT", "key_type", fallback="EC").upper()
    root_ec_curve = pki_cfg.get("ROOT", "ec_curve", fallback="prime256v1")
    root_rsa_bits = pki_cfg.getint("ROOT", "rsa_bits", fallback=4096)

    def dn_from(section):
        return {
            "C": pki_cfg.get(section, "dn_c", fallback=""),
            "ST": pki_cfg.get(section, "dn_st", fallback=""),
            "L": pki_cfg.get(section, "dn_l", fallback=""),
            "O": pki_cfg.get(section, "dn_o", fallback=""),
            "OU": pki_cfg.get(section, "dn_ou", fallback=""),
            "CN": pki_cfg.get(section, "dn_cn", fallback=""),
        }

    root_dn = dn_from("ROOT")
    crl_dp = pki_cfg.get(
        "EXTENSIONS",
        "crl_distribution_points",
        fallback="",
    ).strip()

    subca_ec_enabled = get_bool(pki_cfg, "SUBCA_EC", "enabled", default=True)
    subca_rsa_enabled = get_bool(pki_cfg, "SUBCA_RSA", "enabled", default=True)

    subca_ec_days = pki_cfg.getint("SUBCA_EC", "days", fallback=3650)
    subca_ec_md = pki_cfg.get("SUBCA_EC", "default_md", fallback="sha256")
    subca_ec_curve = pki_cfg.get("SUBCA_EC", "ec_curve", fallback="prime256v1")
    subca_ec_dn = dn_from("SUBCA_EC")

    subca_rsa_days = pki_cfg.getint("SUBCA_RSA", "days", fallback=3650)
    subca_rsa_md = pki_cfg.get("SUBCA_RSA", "default_md", fallback="sha256")
    subca_rsa_bits = pki_cfg.getint("SUBCA_RSA", "rsa_bits", fallback=4096)
    subca_rsa_dn = dn_from("SUBCA_RSA")

    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            root_cnf = temp_path / "rad_ca_root.cnf"
            root_cnf.write_text(
                "\n".join(
                    [
                        "[ req ]",
                        f"default_bits = {root_rsa_bits}",
                        f"default_md = {root_md}",
                        "prompt = no",
                        "distinguished_name = dn",
                        "x509_extensions = v3_ca",
                        "[ dn ]",
                        f"C = {root_dn['C']}",
                        f"ST = {root_dn['ST']}",
                        f"L = {root_dn['L']}",
                        f"O = {root_dn['O']}",
                        f"OU = {root_dn['OU']}",
                        f"CN = {root_dn['CN']}",
                        "[ v3_ca ]",
                        "subjectKeyIdentifier = hash",
                        "authorityKeyIdentifier = keyid:always,issuer",
                        "basicConstraints = critical, CA:true, pathlen:1",
                        "",
                    ]
                ),
                encoding="ascii",
            )

            ca_root_ext = temp_path / "ca_root_ext.cnf"
            ext_lines = [
                "[ v3_intermediate ]",
                "subjectKeyIdentifier = hash",
                "authorityKeyIdentifier = keyid,issuer",
                "basicConstraints = critical, CA:true, pathlen:0",
                "keyUsage = keyCertSign, cRLSign",
            ]
            if crl_dp:
                ext_lines.append(f"crlDistributionPoints = {crl_dp}")
            ext_lines.append("")
            ca_root_ext.write_text("\n".join(ext_lines), encoding="ascii")

            if root_key_type == "EC":
                run_openssl(
                    [
                        "openssl",
                        "ecparam",
                        "-name",
                        root_ec_curve,
                        "-genkey",
                        "-noout",
                        "-out",
                        str(root_key_path),
                    ]
                )
            elif root_key_type == "RSA":
                run_openssl(
                    [
                        "openssl",
                        "genpkey",
                        "-algorithm",
                        "RSA",
                        "-out",
                        str(root_key_path),
                        "-pkeyopt",
                        f"rsa_keygen_bits:{root_rsa_bits}",
                    ]
                )
            else:
                print(f"ERROR: Unsupported ROOT key_type: {root_key_type}", file=sys.stderr)
                return 1

            run_openssl(
                [
                    "openssl",
                    "req",
                    "-config",
                    str(root_cnf),
                    "-key",
                    str(root_key_path),
                    "-new",
                    "-x509",
                    "-days",
                    str(root_days),
                    "-sha256",
                    "-out",
                    str(root_cert_path),
                ]
            )

            serial_path = root_cert_path.with_suffix(".srl")

            if subca_ec_enabled:
                subca_ec_cnf = temp_path / "rad_ca_sub_ec.cnf"
                subca_ec_cnf.write_text(
                    "\n".join(
                        [
                            "[ req ]",
                            "default_bits = 2048",
                            f"default_md = {subca_ec_md}",
                            "prompt = no",
                            "distinguished_name = dn",
                            "req_extensions = v3_intermediate",
                            "[ dn ]",
                            f"C = {subca_ec_dn['C']}",
                            f"ST = {subca_ec_dn['ST']}",
                            f"L = {subca_ec_dn['L']}",
                            f"O = {subca_ec_dn['O']}",
                            f"OU = {subca_ec_dn['OU']}",
                            f"CN = {subca_ec_dn['CN']}",
                            "[ v3_intermediate ]",
                            "subjectKeyIdentifier = hash",
                            "basicConstraints = critical, CA:true, pathlen:0",
                            "keyUsage = keyCertSign, cRLSign",
                            "",
                        ]
                    ),
                    encoding="ascii",
                )

                subca_ec_csr = temp_path / "rad_ca_sub_ec.csr"
                run_openssl(
                    [
                        "openssl",
                        "ecparam",
                        "-name",
                        subca_ec_curve,
                        "-genkey",
                        "-noout",
                        "-out",
                        str(subca_key_path_ec),
                    ]
                )
                run_openssl(
                    [
                        "openssl",
                        "req",
                        "-new",
                        "-config",
                        str(subca_ec_cnf),
                        "-key",
                        str(subca_key_path_ec),
                        "-out",
                        str(subca_ec_csr),
                    ]
                )
                run_openssl(
                    [
                        "openssl",
                        "x509",
                        "-req",
                        "-in",
                        str(subca_ec_csr),
                        "-CA",
                        str(root_cert_path),
                        "-CAkey",
                        str(root_key_path),
                        "-CAserial",
                        str(serial_path),
                        "-CAcreateserial",
                        "-out",
                        str(subca_cert_path_ec),
                        "-days",
                        str(subca_ec_days),
                        "-sha256",
                        "-extfile",
                        str(ca_root_ext),
                        "-extensions",
                        "v3_intermediate",
                    ]
                )

                write_chain(chain_file_path_ec, subca_cert_path_ec, root_cert_path)

            if subca_rsa_enabled:
                subca_rsa_cnf = temp_path / "rad_ca_sub_rsa.cnf"
                subca_rsa_cnf.write_text(
                    "\n".join(
                        [
                            "[ req ]",
                            f"default_bits = {subca_rsa_bits}",
                            f"default_md = {subca_rsa_md}",
                            "prompt = no",
                            "distinguished_name = dn",
                            "req_extensions = v3_intermediate",
                            "[ dn ]",
                            f"C = {subca_rsa_dn['C']}",
                            f"ST = {subca_rsa_dn['ST']}",
                            f"L = {subca_rsa_dn['L']}",
                            f"O = {subca_rsa_dn['O']}",
                            f"OU = {subca_rsa_dn['OU']}",
                            f"CN = {subca_rsa_dn['CN']}",
                            "[ v3_intermediate ]",
                            "subjectKeyIdentifier = hash",
                            "basicConstraints = critical, CA:true, pathlen:0",
                            "keyUsage = keyCertSign, cRLSign",
                            "",
                        ]
                    ),
                    encoding="ascii",
                )

                subca_rsa_csr = temp_path / "rad_ca_sub_rsa.csr"
                run_openssl(
                    [
                        "openssl",
                        "genpkey",
                        "-algorithm",
                        "RSA",
                        "-out",
                        str(subca_key_path_rsa),
                        "-pkeyopt",
                        f"rsa_keygen_bits:{subca_rsa_bits}",
                    ]
                )
                run_openssl(
                    [
                        "openssl",
                        "req",
                        "-new",
                        "-config",
                        str(subca_rsa_cnf),
                        "-key",
                        str(subca_key_path_rsa),
                        "-out",
                        str(subca_rsa_csr),
                    ]
                )
                run_openssl(
                    [
                        "openssl",
                        "x509",
                        "-req",
                        "-in",
                        str(subca_rsa_csr),
                        "-CA",
                        str(root_cert_path),
                        "-CAkey",
                        str(root_key_path),
                        "-CAserial",
                        str(serial_path),
                        "-CAcreateserial",
                        "-out",
                        str(subca_cert_path_rsa),
                        "-days",
                        str(subca_rsa_days),
                        "-sha256",
                        "-extfile",
                        str(ca_root_ext),
                        "-extensions",
                        "v3_intermediate",
                    ]
                )

                write_chain(chain_file_path_rsa, subca_cert_path_rsa, root_cert_path)

    except FileNotFoundError:
        print("ERROR: openssl not found in PATH.", file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as exc:
        print(f"ERROR: OpenSSL command failed: {exc}", file=sys.stderr)
        return 1

    print("OK: Root and sub-CA materials generated.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
