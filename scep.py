"""Compatibility shim.

Enterprise SCEP implementation lives under ``enterprise.scep``.
"""

try:
    from enterprise.scep import *  # noqa: F401,F403
except Exception:
    from flask import Blueprint, abort

    scep_app = Blueprint("scep_app", __name__)

    @scep_app.route("/cgi-bin/pkiclient.exe", methods=["GET", "POST"])
    @scep_app.route("/scep", methods=["GET", "POST"])
    @scep_app.route("/mobileconfig", methods=["GET"])
    def _scep_unavailable():
        return abort(404)
