import os
import io
import subprocess
import tempfile
from datetime import datetime
from flask import Blueprint, request, render_template, redirect, url_for, flash, send_file, make_response, jsonify
from flask_login import login_required, current_user
from extensions import db
from openssl_utils import get_provider_args, is_pqc_available

x509_keys_bp = Blueprint("keys", __name__, template_folder="html_templates")

class Key(db.Model):
    __tablename__ = "keys"
    id         = db.Column(db.Integer,   primary_key=True)
    name       = db.Column(db.String(255), nullable=False)
    key_type   = db.Column(db.String(10),  nullable=False)  # "RSA", "EC" or "PQC"
    key_size   = db.Column(db.Integer,     nullable=True)   # for RSA
    curve_name = db.Column(db.String(50),  nullable=True)   # for EC
    pqc_alg    = db.Column(db.String(20),  nullable=True)   # for PQC, e.g. "mldsa44"
    private_key= db.Column(db.Text,        nullable=False)
    public_key = db.Column(db.Text,        nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id    = db.Column(db.Integer, nullable=True)  # Multi-tenancy


@x509_keys_bp.route("/generate", methods=["GET", "POST"])
@login_required
def generate_key():
    if request.method == "POST":
        key_name = request.form.get("key_name")
        if not key_name:
            flash("Key name is required.", "error")
            return redirect(url_for("keys.generate_key"))

        key_type = request.form.get("key_type")
        key_size = None
        curve_name = None
        pqc_alg   = None
        # temp file for private key
        priv_f = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
        priv_path = priv_f.name
        priv_f.close()

        try:
            if key_type == "RSA":
                key_size = request.form.get("key_size", "2048")
                cmd = ["openssl", "genrsa", "-out", priv_path, key_size]

            elif key_type == "EC":
                curve_name = request.form.get("curve", "prime256v1")
                cmd = ["openssl", "ecparam", "-name", curve_name, "-genkey",
                       "-noout", "-out", priv_path]

            elif key_type == "PQC":
                # pull the PQC algorithm choice
                pqc_alg = request.form.get("pqc_alg", "mldsa44")
                cmd = ["openssl", "genpkey", "-algorithm", pqc_alg]
                # Add provider args only if oqsprovider is available
                cmd.extend(get_provider_args())
                cmd.extend(["-out", priv_path])
            else:
                flash("Invalid key type.", "error")
                os.unlink(priv_path)
                return redirect(url_for("keys.generate_key"))

            subprocess.run(cmd, check=True, capture_output=True, text=True)

        except subprocess.CalledProcessError as e:
            os.unlink(priv_path)
            flash(f"Error generating key: {e.stderr}", "error")
            return redirect(url_for("keys.generate_key"))

        # extract public key
        pub_f = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
        pub_path = pub_f.name
        pub_f.close()

        try:
            pub_cmd = ["openssl", "pkey", "-in", priv_path, "-pubout"]
            # Add provider args if available (needed for PQC keys)
            pub_cmd.extend(get_provider_args())
            pub_cmd.extend(["-out", pub_path])
            subprocess.run(pub_cmd, check=True, capture_output=True, text=True)

        except subprocess.CalledProcessError as e:
            os.unlink(priv_path); os.unlink(pub_path)
            flash(f"Error extracting public key: {e.stderr}", "error")
            return redirect(url_for("keys.generate_key"))

        # read keys
        with open(priv_path) as f: priv_data = f.read()
        with open(pub_path ) as f: pub_data  = f.read()
        os.unlink(priv_path); os.unlink(pub_path)

        # save to DB
        new_key = Key(
            name=key_name,
            key_type=key_type,
            key_size=int(key_size) if key_type == "RSA" else None,
            curve_name=curve_name if key_type == "EC" else None,
            pqc_alg=pqc_alg if key_type == "PQC" else None,
            private_key=priv_data,
            public_key=pub_data,
            created_at=datetime.utcnow(),
            user_id=current_user.id
        )
        db.session.add(new_key)
        db.session.commit()

        flash("Key generated successfully.", "success")
        return redirect(url_for("keys.list_keys"))

    return render_template("generate_key.html", pqc_available=is_pqc_available())

def generate_keyX():
    if request.method == "POST":
        key_name = request.form.get("key_name")
        if not key_name:
            flash("Key name is required.", "error")
            return redirect(url_for("keys.generate_key"))
        key_type = request.form.get("key_type")
        key_size = None
        curve_name = None
        private_key_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
        private_key_filename = private_key_file.name
        private_key_file.close()
        try:
            if key_type == "RSA":
                key_size = request.form.get("key_size", "2048")
                rsa_cmd = ["openssl", "genrsa", "-out", private_key_filename, key_size]
                subprocess.run(rsa_cmd, check=True, capture_output=True, text=True)
            elif key_type == "EC":
                curve_name = request.form.get("curve", "prime256v1")
                ec_cmd = ["openssl", "ecparam", "-name", curve_name, "-genkey", "-noout", "-out", private_key_filename]
                subprocess.run(ec_cmd, check=True, capture_output=True, text=True)
            else:
                flash("Invalid key type selected.", "error")
                os.unlink(private_key_filename)
                return redirect(url_for("keys.generate_key"))
        except subprocess.CalledProcessError as e:
            os.unlink(private_key_filename)
            flash(f"Error generating key: {e.stderr}", "error")
            return redirect(url_for("keys.generate_key"))
        public_key_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
        public_key_filename = public_key_file.name
        public_key_file.close()
        try:
            if key_type == "RSA":
                pub_cmd = ["openssl", "rsa", "-in", private_key_filename, "-pubout", "-out", public_key_filename]
            elif key_type == "EC":
                pub_cmd = ["openssl", "ec", "-in", private_key_filename, "-pubout", "-out", public_key_filename]
            subprocess.run(pub_cmd, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            os.unlink(private_key_filename)
            os.unlink(public_key_filename)
            flash(f"Error extracting public key: {e.stderr}", "error")
            return redirect(url_for("keys.generate_key"))
        with open(private_key_filename, "r") as f:
            private_key_data = f.read()
        with open(public_key_filename, "r") as f:
            public_key_data = f.read()
        os.unlink(private_key_filename)
        os.unlink(public_key_filename)
        new_key = Key(
            name=key_name,
            key_type=key_type,
            key_size=int(key_size) if key_type == "RSA" else None,
            curve_name=curve_name if key_type == "EC" else None,
            private_key=private_key_data,
            public_key=public_key_data,
            created_at=datetime.utcnow()
        )
        db.session.add(new_key)
        db.session.commit()
        flash("Key generated successfully.", "success")
        return redirect(url_for("keys.list_keys"))
    return render_template("generate_key.html")

#@x509_keys_bp.route("/keys", methods=["GET"])
#def list_keys():
#    keys = Key.query.order_by(Key.created_at.desc()).all()
#    return render_template("list_keys.html", keys=keys)


from zoneinfo import ZoneInfo

def check_key_supported(key_obj):
    """Check if a key can be processed. Returns (is_supported, error_message)"""
    if key_obj.key_type == "PQC":
        from openssl_utils import check_oqsprovider_available
        if not check_oqsprovider_available():
            return False, "Unsupported (requires oqsprovider)"
    return True, None

@x509_keys_bp.route("/keys", methods=["GET"])
@login_required
def list_keys():
    if current_user.is_admin():
        keys = Key.query.order_by(Key.created_at.desc()).all()
        # Fetch user info for each key
        from user_models import get_user_by_id
        for k in keys:
            k.user_obj = get_user_by_id(k.user_id) if k.user_id else None
    else:
        keys = Key.query.filter_by(user_id=current_user.id).order_by(Key.created_at.desc()).all()
        for k in keys:
            k.user_obj = current_user

    # convert each key’s created_at to the system tz (or hardcode Asia/Jerusalem)
    local_keys = []
    for k in keys:
        dt = k.created_at
        if dt is not None:
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=ZoneInfo("UTC"))
            dt_local = dt.astimezone()
            k.created_at_local = dt_local
        else:
            k.created_at_local = None
        is_supported, error_msg = check_key_supported(k)
        k.is_supported = is_supported
        k.support_error = error_msg
        local_keys.append(k)
    return render_template("list_keys.html", keys=local_keys, is_admin=current_user.is_admin())


@x509_keys_bp.route("/keys/state", methods=["GET"])
@login_required
def keys_state():
    admin = current_user.is_authenticated and (current_user.is_admin() if callable(getattr(current_user, "is_admin", None)) else getattr(current_user, "is_admin", False))
    query = Key.query
    if not admin:
        query = query.filter_by(user_id=current_user.id)
    count = query.count()
    max_id_row = query.order_by(Key.id.desc()).with_entities(Key.id).first()
    max_id = max_id_row[0] if max_id_row else 0
    return jsonify({"count": count, "max_id": max_id})


@x509_keys_bp.route("/keys/<int:key_id>", methods=["GET"])
@login_required
def view_key(key_id):
    if current_user.is_admin():
        key_obj = Key.query.get_or_404(key_id)
    else:
        key_obj = Key.query.filter_by(id=key_id, user_id=current_user.id).first_or_404()
    return render_template("view_key.html", key=key_obj)


@x509_keys_bp.route("/keys/<int:key_id>/download", methods=["GET"])
@login_required
def download_key(key_id):
    if current_user.is_admin():
        key_obj = Key.query.get_or_404(key_id)
    else:
        key_obj = Key.query.filter_by(id=key_id, user_id=current_user.id).first_or_404()
    pem_bytes = key_obj.private_key.encode("utf-8")
    buf = io.BytesIO(pem_bytes)
    buf.seek(0)
    return send_file(
        buf,
        as_attachment=True,
        download_name=f"{key_obj.name}.pem",
        mimetype="application/x-pem-file"
    )



@x509_keys_bp.route("/keys/<int:key_id>/delete", methods=["POST"])
@login_required
def delete_key(key_id):
    if current_user.is_admin():
        key_obj = Key.query.get_or_404(key_id)
    else:
        key_obj = Key.query.filter_by(id=key_id, user_id=current_user.id).first_or_404()
    db.session.delete(key_obj)
    db.session.commit()
    flash("Key deleted successfully.", "success")
    return redirect(url_for("keys.list_keys"))

