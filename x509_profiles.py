import os
import re
import subprocess
import tempfile
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
from jinja2 import Environment, meta, FileSystemLoader
from extensions import db

x509_profiles_bp = Blueprint("profiles", __name__, template_folder="html_templates")

from flask_login import current_user, login_required
class Profile(db.Model):
    __tablename__ = "profiles"
    id            = db.Column(db.Integer, primary_key=True)
    filename      = db.Column(db.String(255), unique=True, nullable=False)
    template_name = db.Column(db.String(255), nullable=False)
    profile_type  = db.Column(db.String(255), nullable=True)
    user_id       = db.Column(db.Integer, nullable=True, index=True)

basedir = os.path.abspath(os.path.dirname(__file__))
X509_TEMPLATE_DIR = os.path.join(basedir, "x509_templates")
X509_PROFILE_DIR  = os.path.join(basedir, "x509_profiles")
os.makedirs(X509_PROFILE_DIR, exist_ok=True)

DUMMY_KEY_PATH = os.path.join(basedir, "dummy.key")


def get_default_for_variable(template_source, var):
    pattern = r"\{\{\s*" + re.escape(var) + r"\s*\|\s*default\((['\"])(.*?)\1"
    m = re.search(pattern, template_source)
    return m.group(2) if m else ""


def _extract_first_section(config_text: str) -> str:
    for line in config_text.splitlines():
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            return line[1:-1].strip()  # <-- FIX: trim section name
    return None

def _validate_cnf(path: str) -> (bool, str):
    if not os.path.exists(DUMMY_KEY_PATH):
        return False, f"Missing dummy key at {DUMMY_KEY_PATH}"

    with open(path, "r", encoding="utf-8") as f:
        config_text = f.read()

    is_csr_template = re.search(r"^\s*CN\s*=", config_text, re.MULTILINE) is not None

    if is_csr_template:
        cmd = [
            "openssl", "req",
            "-new",
            "-config", path,
            "-key", DUMMY_KEY_PATH,
            "-noout"
        ]
        print("🔧 CSR Validation Command:")
        print(" ".join(cmd))
        proc = subprocess.run(cmd, capture_output=True, text=True)
        print("\n🔍 OpenSSL Output:")
        print(proc.stderr or proc.stdout)
        return (proc.returncode == 0, proc.stderr or proc.stdout)

    # Extension-only config
    ca_cert = current_app.config.get("SUBCA_CERT_PATH")
    ca_key  = current_app.config.get("SUBCA_KEY_PATH")

    if not ca_cert or not ca_key or not os.path.exists(ca_cert) or not os.path.exists(ca_key):
        return False, "Missing or invalid SUBCA cert/key path from app config"

    ext_section = _extract_first_section(config_text)
    if not ext_section:
        return False, "Could not determine extension section name"

    # Create persistent temp files for debug
    csr_file = tempfile.NamedTemporaryFile(suffix=".csr", delete=False)
    crt_file = tempfile.NamedTemporaryFile(suffix=".crt", delete=False)

    try:
        csr_path = csr_file.name
        crt_path = crt_file.name
        csr_file.close()
        crt_file.close()

        # Generate CSR
        csr_cmd = [
            "openssl", "req", "-new",
            "-key", DUMMY_KEY_PATH,
            "-subj", "/CN=dummy",
            "-out", csr_path
        ]
        print("🔧 CSR Generation Command:")
        print(" ".join(csr_cmd))
        subprocess.run(csr_cmd, check=True)

        # Show contents of the -extfile path before running the OpenSSL command
        print(f"\n📄 Contents of -extfile: {path}")
        try:
            with open(path, 'r') as f:
                print(f.read())
        except Exception as read_err:
            print(f"⚠️ Could not read extension file: {read_err}")

        # Sign CSR with extension config
        sign_cmd = [
            "openssl", "x509", "-req",
            "-in", csr_path,
            "-CA", ca_cert,
            "-CAkey", ca_key,
            "-CAcreateserial",
            "-out", crt_path,
            "-days", "1",
            "-extfile", path,
            "-extensions", ext_section
        ]
        print("🔧 Extension Validation Command:")
        print(" ".join(sign_cmd))

        proc = subprocess.run(sign_cmd, capture_output=True, text=True)

        print("\n🔍 OpenSSL Output:")
        print(proc.stderr or proc.stdout)

        return (proc.returncode == 0, proc.stderr or proc.stdout)

    except subprocess.CalledProcessError as e:
        print("❌ OpenSSL Exception Raised:")
        print(e.stderr or e.stdout)
        return False, f"OpenSSL error: {e.stderr or e.stdout}"



def _validate_cnf_disable(path: str) -> (bool, str):
    # always use the project-root dummy.key
    if not os.path.exists(DUMMY_KEY_PATH):
        return False, f"Missing dummy key at {DUMMY_KEY_PATH}"
    cmd = [
        "openssl", "req",
        "-new",
        "-config", path,
        "-key",     DUMMY_KEY_PATH,
        "-noout"
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return (proc.returncode == 0, proc.stderr or proc.stdout)


#
# 1) LIST TEMPLATES  ← explicit endpoint name
#
@x509_profiles_bp.route("/x509_templates/", endpoint="list_templates", methods=["GET"])
@login_required
def list_templates():
    template_files = [f for f in os.listdir(X509_TEMPLATE_DIR) if f.endswith(".j2")]
    return render_template("list_templates.html", template_files=template_files)

#
# 2) RENDER A NEW PROFILE
#
@x509_profiles_bp.route("/template", methods=["GET", "POST"])
@login_required
def template_form():
    template_name = request.args.get("template")
    if not template_name:
        return redirect(url_for("profiles.list_templates"))

    env = Environment(loader=FileSystemLoader(X509_TEMPLATE_DIR))
    source, _, _ = env.loader.get_source(env, template_name)
    parsed = env.parse(source)
    variables = sorted(meta.find_undeclared_variables(parsed))
    defaults = {v: get_default_for_variable(source, v) for v in variables}
    existing_types = [pt for (pt,) in db.session.query(Profile.profile_type).distinct().all() if pt]

    if request.method == "POST":
        data      = {v: request.form.get(v, "") for v in variables}
        outname   = request.form.get("rendered_filename") or template_name[:-3]
        prof_type = request.form.get("profile_type", "")
        rendered  = env.get_template(template_name).render(data)

        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".cnf")
        tmp.write(rendered.encode("utf-8"))
        tmp.flush(); tmp.close()
        ok, err = _validate_cnf(tmp.name)
        os.unlink(tmp.name)
        if not ok:
            flash(f"Syntax error in rendered profile:\n{err}", "error")
            return redirect(url_for("profiles.template_form", template=template_name))

        outpath = os.path.join(X509_PROFILE_DIR, outname)
        # Normalize line endings and collapse multiple blank lines
        import re
        rendered_normalized = rendered.replace('\r\n', '\n').replace('\r', '\n')
        rendered_normalized = re.sub(r'\n{3,}', '\n\n', rendered_normalized)
        with open(outpath, "w", newline='') as f:
            f.write(rendered_normalized)

        prof = Profile.query.filter_by(filename=outname).first()
        if not prof:
            prof = Profile(filename=outname, template_name=template_name, profile_type=prof_type, user_id=current_user.id)
            db.session.add(prof)
        else:
            prof.template_name = template_name
            prof.profile_type  = prof_type
            # Only allow update if admin or owner
            if not (current_user.is_admin or prof.user_id == current_user.id):
                flash("Not authorized to update this profile.", "error")
                return redirect(url_for("profiles.list_profiles"))
        db.session.commit()

        return render_template("profile_result.html",
                               rendered_template=rendered,
                               template_name=outname,
                               profile=prof,
                               profile_template=template_name,
                               profile_type=prof_type,
                               variables_values=data)

    return render_template("template_form.html",
                           variables=variables,
                           template_name=template_name,
                           default_rendered_name=template_name[:-3],
                           variables_values=defaults,
                           existing_types=existing_types)

#
# 3) LIST SAVED PROFILES
#
@x509_profiles_bp.route("/profiles/", methods=["GET"])
@login_required
def list_profiles():
    if current_user.is_authenticated and current_user.is_admin():
        profiles = Profile.query.order_by(Profile.id.desc()).all()
        from user_models import get_user_by_id
        for p in profiles:
            p.user_obj = get_user_by_id(p.user_id) if p.user_id else None
        is_admin = True
    else:
        profiles = Profile.query.filter_by(user_id=current_user.id).order_by(Profile.id.desc()).all()
        for p in profiles:
            p.user_obj = current_user
        is_admin = False
    return render_template("list_profiles.html", profiles=profiles, is_admin=is_admin)

#
# 4) VIEW A RENDERED PROFILE
#
@x509_profiles_bp.route("/profiles/<filename>", methods=["GET"])
@login_required
def view_profile(filename):
    path = os.path.join(X509_PROFILE_DIR, filename)
    if not os.path.exists(path):
        return f"File {filename} not found.", 404
    content = open(path).read()
    prof = Profile.query.filter_by(filename=filename).first()
    # Only allow view if admin or owner
    if not prof or (not (current_user.is_admin or prof.user_id == current_user.id)):
        flash("Not authorized to view this profile.", "error")
        return redirect(url_for("profiles.list_profiles"))
    return render_template("profile_file.html",
                           filename=filename,
                           file_content=content,
                           profile=prof)

#
# 5) EDIT A RENDERED PROFILE
#
@x509_profiles_bp.route("/profiles/edit/<filename>", methods=["GET", "POST"])
@login_required
def edit_profile_file(filename):
    filepath = os.path.join(X509_PROFILE_DIR, filename)
    if not os.path.exists(filepath):
        flash(f"Profile {filename} not found.", "error")
        return redirect(url_for("profiles.list_profiles"))

    if request.method == "POST":
        new_content = request.form.get("file_content", "")
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".cnf")
        tmp.write(new_content.encode("utf-8"))
        tmp.flush(); tmp.close()
        ok, err = _validate_cnf(tmp.name)
        os.unlink(tmp.name)
        if not ok:
            flash(f"Syntax error in profile:\n{err}", "error")
            return redirect(url_for("profiles.edit_profile_file", filename=filename))

        try:
            import re
            new_content_normalized = new_content.replace('\r\n', '\n').replace('\r', '\n')
            new_content_normalized = re.sub(r'\n{3,}', '\n\n', new_content_normalized)
            with open(filepath, "w", newline='') as f:
                f.write(new_content_normalized)
            flash(f"Profile {filename} updated.", "success")
        except Exception as e:
            flash(f"Failed to save: {e}", "error")

        return redirect(url_for("profiles.view_profile", filename=filename))

    content = open(filepath).read()
    prof    = Profile.query.filter_by(filename=filename).first()
    # Only allow edit if admin or owner
    if not prof or (not (current_user.is_admin or prof.user_id == current_user.id)):
        flash("Not authorized to edit this profile.", "error")
        return redirect(url_for("profiles.list_profiles"))
    return render_template("edit_profile.html",
                           filename=filename,
                           file_content=content,
                           profile=prof)

#
# 6) DELETE
#
@x509_profiles_bp.route("/profiles/delete/<filename>", methods=["POST"])
@login_required
def delete_profile(filename):
    path = os.path.join(X509_PROFILE_DIR, filename)
    if os.path.exists(path):
        os.remove(path)
    prof = Profile.query.filter_by(filename=filename).first()
    # Only allow delete if admin or owner
    if prof and (current_user.is_admin or prof.user_id == current_user.id):
        db.session.delete(prof)
        db.session.commit()
    else:
        flash("Not authorized to delete this profile.", "error")
    return redirect(url_for("profiles.list_profiles"))

#
# 7) NEW PROFILE
#
import re

def is_valid_profile_filename(filename):
    # Must end with .cnf and be a valid Linux filename (no /, \0, etc.)
    return (
        filename.endswith('.cnf') and
        re.match(r'^[\w\-.]+\.cnf$', filename) is not None
    )

@x509_profiles_bp.route("/profiles/new", methods=["GET", "POST"])
@login_required
def new_profile_file():
    # Get all existing profile types for the dropdown
    existing_types = [pt for (pt,) in db.session.query(Profile.profile_type).distinct().all() if pt]

    if request.method == "POST":
        filename = request.form.get("filename", "").strip()
        profile_type = request.form.get("profile_type", "").strip()
        new_content = request.form.get("file_content", "")
        if not is_valid_profile_filename(filename):
            flash("Profile File Name must be a valid Linux filename ending with .cnf", "error")
            return render_template("edit_profile.html",
                                   filename="",
                                   profile_type=profile_type,
                                   file_content=new_content,
                                   profile=None,
                                   existing_types=existing_types)
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".cnf")
        tmp.write(new_content.encode("utf-8"))
        tmp.flush(); tmp.close()
        ok, err = _validate_cnf(tmp.name)
        os.unlink(tmp.name)
        if not ok:
            flash(f"Syntax error in profile:\n{err}", "error")
            return redirect(url_for("profiles.new_profile_file"))

        try:
            import re
            new_content_normalized = new_content.replace('\r\n', '\n').replace('\r', '\n')
            new_content_normalized = re.sub(r'\n{3,}', '\n\n', new_content_normalized)
            outpath = os.path.join(X509_PROFILE_DIR, filename)
            with open(outpath, "w", newline='') as f:
                f.write(new_content_normalized)
            prof = Profile(filename=filename, template_name="", profile_type=profile_type, user_id=current_user.id)
            db.session.add(prof)
            db.session.commit()
            flash(f"Profile {filename} created.", "success")
            return redirect(url_for("profiles.view_profile", filename=filename))
        except Exception as e:
            flash(f"Failed to save: {e}", "error")
            return redirect(url_for("profiles.new_profile_file"))

    # GET: render the same form as edit, but blank, and pass existing_types
    return render_template("edit_profile.html",
                           filename="",
                           profile_type="",
                           file_content="",
                           profile=None,
                           existing_types=existing_types)

