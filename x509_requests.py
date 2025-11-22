import os
import subprocess
import tempfile
from datetime import datetime
from flask import Blueprint, request, render_template, redirect, url_for, flash, current_app
from extensions import db
from flask import send_file
from openssl_utils import get_provider_args
import io
x509_requests_bp = Blueprint("requests", __name__, template_folder="html_templates")

class CSR(db.Model):
    __tablename__ = "csrs"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    key_id = db.Column(db.Integer, nullable=False)
    profile_id = db.Column(db.Integer, nullable=False)
    csr_pem = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


@x509_requests_bp.route("/requests/<int:csr_id>/download", methods=["GET"])
def download_csr(csr_id):
    csr_obj = CSR.query.get_or_404(csr_id)
    # create an in-memory file
    buf = io.BytesIO(csr_obj.csr_pem.encode("utf-8"))
    buf.seek(0)
    # use CSR name for download filename
    filename = f"{csr_obj.name}.csr"
    return send_file(
        buf,
        as_attachment=True,
        download_name=filename,
        mimetype="application/pkcs10"
    )




@x509_requests_bp.route("/requests/generate", methods=["GET", "POST"])
def generate_csr():
    if request.method == "POST":
        csr_name = request.form.get("csr_name")
        key_id = request.form.get("key_id")
        profile_id = request.form.get("profile_id")
        if not csr_name or not key_id or not profile_id:
            flash("All fields are required.", "error")
            return redirect(url_for("requests.generate_csr"))
        from x509_keys import Key
        from x509_profiles import Profile
        key_obj = Key.query.get(key_id)
        profile_obj = Profile.query.get(profile_id)
        if not key_obj or not profile_obj:
            flash("Invalid selection.", "error")
            return redirect(url_for("requests.generate_csr"))
        temp_key_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
        temp_key_file.write(key_obj.private_key.encode())
        temp_key_file.close()
        temp_key_filename = temp_key_file.name
        temp_csr_file = tempfile.NamedTemporaryFile(delete=False, suffix=".csr")
        temp_csr_file.close()
        temp_csr_filename = temp_csr_file.name
        config_file = os.path.abspath(os.path.join(os.getcwd(), "x509_profiles", profile_obj.filename))
        current_app.logger.debug("Using config file: %s", config_file)
        cmd = ["openssl", "req"]
        cmd.extend(get_provider_args())
        cmd.extend(["-new", "-config", config_file, "-key", temp_key_filename, "-out", temp_csr_filename])
        current_app.logger.debug("Running: %s", " ".join(cmd))
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
#            os.unlink(temp_key_filename)
#            os.unlink(temp_csr_filename)
            flash(f"Error generating CSR: {e.stderr}", "error")
            return redirect(url_for("requests.generate_csr"))
        with open(temp_csr_filename, "r") as f:
            csr_pem = f.read()
        os.unlink(temp_key_filename)
        os.unlink(temp_csr_filename)
        new_csr = CSR(name=csr_name, key_id=key_obj.id, profile_id=profile_obj.id, csr_pem=csr_pem, created_at=datetime.utcnow())
        db.session.add(new_csr)
        db.session.commit()
        flash("CSR created successfully.", "success")
        return redirect(url_for("requests.list_csrs"))
    from x509_keys import Key
    from x509_profiles import Profile
    keys = Key.query.order_by(Key.created_at.desc()).all()
    profiles = Profile.query.order_by(Profile.id.desc()).all()
    return render_template("generate_csr.html", keys=keys, profiles=profiles)

@x509_requests_bp.route("/requests", methods=["GET"])
def list_csrs():
    csrs = CSR.query.order_by(CSR.created_at.desc()).all()
    from x509_keys import Key
    from x509_profiles import Profile
    keys = Key.query.all()
    profiles = Profile.query.all()
    key_dict = {key.id: key for key in keys}
    profile_dict = {profile.id: profile for profile in profiles}
    return render_template("list_csrs.html", csrs=csrs, key_dict=key_dict, profile_dict=profile_dict)

@x509_requests_bp.route("/requests/<int:csr_id>", methods=["GET"])
def view_csr(csr_id):
    csr_obj = CSR.query.get_or_404(csr_id)
    from x509_keys import Key
    from x509_profiles import Profile
    key_obj = Key.query.get(csr_obj.key_id)
    profile_obj = Profile.query.get(csr_obj.profile_id)
    profile_content = ""
    if profile_obj:
        config_file_path = os.path.join(current_app.root_path, "x509_profiles", profile_obj.filename)
        if os.path.exists(config_file_path):
            try:
                with open(config_file_path, "r") as f:
                    profile_content = f.read()
            except Exception as e:
                current_app.logger.error("Error reading config: %s", e)
    return render_template("view_csr.html", csr=csr_obj, key=key_obj, profile=profile_obj, profile_content=profile_content)

@x509_requests_bp.route("/requests/<int:csr_id>/delete", methods=["POST"])
def delete_csr(csr_id):
    csr_obj = CSR.query.get_or_404(csr_id)
    db.session.delete(csr_obj)
    db.session.commit()
    flash("CSR deleted successfully.", "success")
    return redirect(url_for("requests.list_csrs"))

