# config_bp.py

import os
from flask import Blueprint, current_app, render_template

config_bp = Blueprint("config", __name__, template_folder="html_templates")

@config_bp.route("/config", methods=["GET"])
def view_config():
  # compute path now that we're in a request context
  config_path = os.path.join(current_app.root_path, "config.ini")
  try:
    with open(config_path, "r") as f:
      content = f.read()
  except FileNotFoundError:
    content = "# config.ini not found\n"
  return render_template("config.html", content=content)

