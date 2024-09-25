#!/usr/bin/env python3
"""Flask app module that handles the app initialization."""

from flask import (
    Flask,
    jsonify,
    request
)
from auth import Auth


app = Flask(__name__)

# Instantiate the Auth object
AUTH = Auth()


@app.route('/', methods=['GET'])
def welcome() -> str:
    """Return a welcome message."""
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods=['POST'])
def register_user() -> str:
    """POST /users route handler that registers a new user."""

    email = request.form.get('email')
    password = request.form.get('password')

    try:
        # Register the user using Auth
        user = AUTH.register_user(email, password)
        return jsonify({"email": user.email, "message": "user created"}), 200
    except ValueError:
        # If the user already exists, return error message
        return jsonify({"message": "email already registered"}), 400


if __name__ == "__main__":4s
    app.run(host="0.0.0.0", port="5000")
