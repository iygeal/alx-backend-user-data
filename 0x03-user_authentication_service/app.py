#!/usr/bin/env python3
"""Flask app module that handles the app initialization."""

from flask import (
    Flask,
    jsonify,
    request,
    abort,
    make_response,
    url_for,
    redirect
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


@app.route("/sessions", methods=['POST'])
def login():
    """POST /sessions route handler that logs in a user."""
    # Get the email and password from the form data
    email = request.form.get('email')
    password = request.form.get('password')

    # Validate the credentials
    if not AUTH.valid_login(email, password):
        abort(401)

    # Create a session ID for the user
    session_id = AUTH.create_session(email)

    # If session ID is generated, set the session cookie and return response
    if session_id:
        res = make_response(jsonify({"email": email, "message": "logged in"}))

        # Set the session_id in the response cookie
        res.set_cookie("session_id", session_id)

        return res

    # If something goes wrong, abort with an error
    abort(401)


@app.route("/sessions", methods=['DELETE'])
def logout():
    """DELETE /sessions route handler that logs out a user."""

    # Retrieve the session ID from cookies
    session_id = request.cookies.get("session_id")

    if session_id is None:
        # If no session ID is found, abort with 403 error
        abort(403)

    # Get the user corresponding to the session ID
    user = AUTH.get_user_from_session_id(session_id)
    if user is None:
        abort(403)

    # Destroy the session for the user
    AUTH.destroy_session(user.id)

    # Redirect to the home page
    return redirect(url_for("welcome"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
