from flask import Flask, render_template, request, redirect, url_for, session
from flask_session import Session
from crypting import LatticeCrypto, load_private_key, save_private_key
from database import init_db, store_user, get_user_data, store_session, delete_session, get_session_user, user_exists
from oqs import Signature
import os
import secrets
import time

app = Flask(__name__)
app.config["SECRET_KEY"] = secrets.token_hex(16)
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

crypto = LatticeCrypto()

@app.route("/")
def idx():
    #render_template("login.html", avg_sign_time=crypto.avg_sign_time)
    return redirect(url_for("login")) 

@app.route("/register", methods=["GET", "POST"])
def register():
    """
    Handles registration logic with /register route supporting both GET and POST.
    """
    if request.method == "POST":
        user_id = request.form["user_id"]
        # Check if user already exists
        if user_exists(user_id):
            return render_template("register.html", error="User ID already exists. "
                                                "Please choose a different ID.")
        public_key, private_key = crypto.generate_keypair()
        store_user(user_id, public_key, crypto.algorithm)  # Store variant
        f_path = save_private_key(user_id, private_key)
        #return redirect(url_for("login"))
        return render_template("register.html", skey=f_path)
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Handles login page logic with /login route supports both GET and POST.
    """
    if request.method == "POST":
        user_id = request.form["user_id"]
        public_key, variant = get_user_data(user_id)
        if not public_key:
            return render_template("login.html", error="User not found")
        
        # Generate challenge
        challenge = secrets.token_bytes(32)
        session["challenge"] = challenge
        session["user_id"] = user_id
        session["variant"] = variant  # Store variant for verification
        return render_template("login.html", challenge=challenge.hex(), step="sign")
    
    return render_template("login.html", avg_sign_time=crypto.avg_sign_time)

@app.route("/verify", methods=["POST"])
def verify():
    """
    Handles signature verification querying and logic  with /verify route
    supporting POST only
    """
    user_id = session.get("user_id")
    challenge = session.get("challenge")
    variant = session.get("variant")
    if not user_id or not challenge or not variant:
        #return redirect(url_for("login"))
        return render_template("login.html", error="Invalid user/challenge, try again...", 
                               step="sign", user_id=user_id, challenge=challenge.hex()
        )
    try:
        signature = bytes.fromhex(request.form["signature"])
    except:
        return render_template("login.html", error="Invalid signature, try again...", 
                               step="sign", user_id=user_id, challenge=challenge.hex()
        )
        #return redirect(url_for("login"))
    public_key, _ = get_user_data(user_id)
    
    # Initialize signature object with correct variant
    crypto_verify = LatticeCrypto() if variant == crypto.algorithm else Signature(variant)
    if crypto_verify.verify(challenge, signature, public_key):
        session_token = secrets.token_hex(16)
        expiry = int(time.time()) + 30  # 0.5 hour expiry
        store_session(session_token, user_id, expiry)
        session["session_token"] = session_token
        print("=============PASSED=============") # for debugging
        return redirect(url_for("index"))
    else:
        return render_template("login.html", error="Invalid signature, try again...", 
                               step="sign", user_id=user_id, challenge=challenge.hex()
        )

@app.route("/logout")
def logout():
    """
    Clear the user session and delete session token from database.
    """
    session_token = session.get("session_token")
    if session_token:
        delete_session(session_token)  # Removes user's session from database
    session.clear()  # Clear Flask session
    return redirect(url_for("index"))

@app.route("/index")
def index():
    """
    Handles user logged in session logic"""
    session_token = session.get("session_token")
    if not session_token:
        print("NO SESSION")
        return redirect(url_for("login"))
    
    user_id = get_session_user(session_token)
    if not user_id:
        print("NO USER")
        return redirect(url_for("login"))
    
    return render_template("index.html", user_id=user_id)

if __name__ == "__main__":
    init_db() # Initialises database connection
    app.run(ssl_context="adhoc", debug=True)  # testingf