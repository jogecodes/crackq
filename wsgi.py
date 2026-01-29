#!/usr/bin/env python
import os
import sys

sys.path.insert(0, "/opt/crackq/build")
sys.path.insert(0, "/opt/crackq/build/crackq")

from crackq import app
from flask import send_from_directory

# Disable CSRF protection and fix session cookies for HTTP access
try:
    # Disable CSRF protection
    from crackq import csrf

    csrf._exempt_views.add("Login")
    csrf._exempt_views.add("login")
    csrf._exempt_views.add("api/login")
    app.config["WTF_CSRF_ENABLED"] = False

    # Allow session cookies over HTTP
    app.config["SESSION_COOKIE_SECURE"] = False

    print("CSRF protection disabled and session cookies enabled for HTTP")
except Exception as e:
    print(f"CSRF/Session configuration error: {e}")

# Initialize database on startup
try:
    with app.app_context():
        from crackq import db

        db.create_all()
        print("Database initialized successfully")
except Exception as e:
    print(f"Database initialization error: {e}")

DIST_DIR = "/opt/crackq/source/dist"


# Add static file routes to the existing CrackQ app
@app.route("/")
def serve_index():
    return send_from_directory(DIST_DIR, "index.html")


@app.route("/css/<path:filename>")
def serve_css(filename):
    return send_from_directory(os.path.join(DIST_DIR, "css"), filename)


@app.route("/js/<path:filename>")
def serve_js(filename):
    return send_from_directory(os.path.join(DIST_DIR, "js"), filename)


@app.route("/img/<path:filename>")
def serve_img(filename):
    return send_from_directory(os.path.join(DIST_DIR, "img"), filename)


@app.route("/favicon.ico")
def serve_favicon():
    return send_from_directory(DIST_DIR, "favicon.ico")


# Handle SPA routing for any non-API routes
@app.errorhandler(404)
def handle_404(e):
    # If it's not an API route, serve the SPA
    from flask import request

    if not request.path.startswith("/api/"):
        return send_from_directory(DIST_DIR, "index.html")
    return e


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
