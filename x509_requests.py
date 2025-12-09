import os
import subprocess
import tempfile
from datetime import datetime
from flask import Blueprint, request, render_template, redirect, url_for, flash, current_app, jsonify
from extensions import db
from flask import send_file
from openssl_utils import get_provider_args
import io
x509_requests_bp = Blueprint("requests", __name__, template_folder="html_templates")

from flask_login import current_user, login_required
class CSR(db.Model):
    __tablename__ = "csrs"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    key_id = db.Column(db.Integer, nullable=False)
    profile_id = db.Column(db.Integer, nullable=False)
    csr_pem = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, nullable=True, index=True)


@x509_requests_bp.route("/requests/<int:csr_id>/download", methods=["GET"])
@login_required
def download_csr(csr_id):
    csr_obj = CSR.query.get_or_404(csr_id)
    # Only allow download if admin or owner
    if not (current_user.is_admin or csr_obj.user_id == current_user.id):
        flash("Not authorized to download this CSR.", "error")
        return redirect(url_for("requests.list_csrs"))
    buf = io.BytesIO(csr_obj.csr_pem.encode("utf-8"))
    buf.seek(0)
    filename = f"{csr_obj.name}.csr"
    return send_file(
        buf,
        as_attachment=True,
        download_name=filename,
        mimetype="application/pkcs10"
    )




@x509_requests_bp.route("/requests/generate", methods=["GET", "POST"])
@login_required
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
        
        # Write profile content to temporary file
        temp_config_file = tempfile.NamedTemporaryFile(delete=False, suffix=".cnf", mode='w', encoding='utf-8')
        temp_config_file.write(profile_obj.content if profile_obj.content else "")
        temp_config_file.close()
        config_file = temp_config_file.name
        
        temp_key_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
        temp_key_file.write(key_obj.private_key.encode())
        temp_key_file.close()
        temp_key_filename = temp_key_file.name
        temp_csr_file = tempfile.NamedTemporaryFile(delete=False, suffix=".csr")
        temp_csr_file.close()
        temp_csr_filename = temp_csr_file.name
        current_app.logger.debug("Using config file: %s", config_file)
        cmd = ["openssl", "req"]
        cmd.extend(get_provider_args())
        cmd.extend(["-new", "-config", config_file, "-key", temp_key_filename, "-out", temp_csr_filename])
        current_app.logger.debug("Running: %s", " ".join(cmd))
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            os.unlink(config_file)
            os.unlink(temp_key_filename)
            os.unlink(temp_csr_filename)
            flash(f"Error generating CSR: {e.stderr}", "error")
            return redirect(url_for("requests.generate_csr"))
        with open(temp_csr_filename, "r") as f:
            csr_pem = f.read()
        os.unlink(config_file)
        os.unlink(temp_key_filename)
        os.unlink(temp_csr_filename)
        new_csr = CSR(name=csr_name, key_id=key_obj.id, profile_id=profile_obj.id, csr_pem=csr_pem, created_at=datetime.utcnow(), user_id=current_user.id)
        db.session.add(new_csr)
        db.session.commit()
        # Event logging
        try:
            from events import log_event
            log_event(
                event_type="create",
                resource_type="request",
                resource_name=csr_name,
                user_id=current_user.id,
                details={"key_id": key_obj.id, "profile_id": profile_obj.id}
            )
        except Exception:
            pass
        flash("CSR created successfully.", "success")
        return redirect(url_for("requests.list_csrs"))
    from x509_keys import Key
    from x509_profiles import Profile
    # Only show profiles with [ req ] section in their content
    if current_user.is_authenticated and hasattr(current_user, 'is_admin') and current_user.is_admin():
        keys = Key.query.order_by(Key.created_at.desc()).all()
        profiles = [p for p in Profile.query.order_by(Profile.id.desc()).all() if p.content and '[ req ]' in p.content]
    else:
        keys = Key.query.filter_by(user_id=current_user.id).order_by(Key.created_at.desc()).all()
        profiles = [p for p in Profile.query.filter_by(user_id=current_user.id).order_by(Profile.id.desc()).all() if p.content and '[ req ]' in p.content]
    return render_template("generate_csr.html", keys=keys, profiles=profiles)


@x509_requests_bp.route("/requests", methods=["GET"])
@login_required
def list_csrs():
    if current_user.is_authenticated and current_user.is_admin():
        csrs = CSR.query.order_by(CSR.created_at.desc()).all()
        from user_models import get_user_by_id
        for csr in csrs:
            csr.user_obj = get_user_by_id(csr.user_id) if csr.user_id else None
        is_admin = True
    else:
        csrs = CSR.query.filter_by(user_id=current_user.id).order_by(CSR.created_at.desc()).all()
        for csr in csrs:
            csr.user_obj = current_user
        is_admin = False
    from x509_keys import Key
    from x509_profiles import Profile
    keys = Key.query.all()
    profiles = Profile.query.all()
    key_dict = {key.id: key for key in keys}
    profile_dict = {profile.id: profile for profile in profiles}
    return render_template("list_csrs.html", csrs=csrs, key_dict=key_dict, profile_dict=profile_dict, is_admin=is_admin)


@x509_requests_bp.route("/requests/state", methods=["GET"])
@login_required
def csrs_state():
    admin = current_user.is_authenticated and (current_user.is_admin() if callable(getattr(current_user, "is_admin", None)) else getattr(current_user, "is_admin", False))
    query = CSR.query
    if not admin:
        query = query.filter_by(user_id=current_user.id)
    count = query.count()
    max_id_row = query.order_by(CSR.id.desc()).with_entities(CSR.id).first()
    max_id = max_id_row[0] if max_id_row else 0
    return jsonify({"count": count, "max_id": max_id})

@x509_requests_bp.route("/requests/<int:csr_id>", methods=["GET"])
@login_required
def view_csr(csr_id):
    csr_obj = CSR.query.get_or_404(csr_id)
    # Only allow view if admin or owner
    if not (current_user.is_admin or csr_obj.user_id == current_user.id):
        flash("Not authorized to view this CSR.", "error")
        return redirect(url_for("requests.list_csrs"))
    from x509_keys import Key
    from x509_profiles import Profile
    key_obj = Key.query.get(csr_obj.key_id)
    profile_obj = Profile.query.get(csr_obj.profile_id)
    profile_content = ""
    if profile_obj and profile_obj.content:
        profile_content = profile_obj.content
    return render_template("view_csr.html", csr=csr_obj, key=key_obj, profile=profile_obj, profile_content=profile_content)

@x509_requests_bp.route("/requests/<int:csr_id>/delete", methods=["POST"])
@login_required
def delete_csr(csr_id):
    csr_obj = CSR.query.get_or_404(csr_id)
    # Only allow delete if admin or owner
    if current_user.is_admin or csr_obj.user_id == current_user.id:
        db.session.delete(csr_obj)
        db.session.commit()
        # Event logging
        try:
            from events import log_event
            log_event(
                event_type="delete",
                resource_type="request",
                resource_name=csr_obj.name,
                user_id=current_user.id,
                details={}
            )
        except Exception:
            pass
        flash("CSR deleted successfully.", "success")
    else:
        flash("Not authorized to delete this CSR.", "error")
    return redirect(url_for("requests.list_csrs"))

# AJAX endpoint for profile content preview
@x509_requests_bp.route("/requests/profile_content", methods=["GET"])
@login_required
def profile_content():
    profile_id = request.args.get("profile_id")
    if not profile_id:
        return "No profile ID provided", 400
    from x509_profiles import Profile
    profile = Profile.query.get(profile_id)
    if not profile or not profile.content:
        return "Profile not found or empty", 404
    return profile.content, 200, {'Content-Type': 'text/plain; charset=utf-8'}

