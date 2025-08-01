from flask import Flask, render_template, request, redirect, url_for, session
from flask_session import Session
from crypting import LatticeCrypto, save_private_key
from database import init_db, store_user, get_user_data, store_session, delete_session, get_session_user, user_exists, get_all_users
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

    # Data being sent from front-end to back-end
    if request.method == "POST":
        user_id = request.form["user_id"]

        # Check if user already exists
        if user_exists(user_id):
            return render_template("register.html", 
                error="User ID already exists. "
                    "Please choose a different ID.")

        # Generate key pair upon registration
        public_key, private_key = crypto.generate_keypair()
        # Store new user in database
        store_user(user_id, public_key, crypto.algorithm)
        
        # Save private key locally on device
        f_path = save_private_key(user_id, private_key)
        #return redirect(url_for("login"))

        # Display template with private key file path 
        # to locate for user
        return render_template("register.html", skey=f_path)
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Handles login page logic with /login route supports both GET and POST.
    """

    if request.method == "POST":
        user_id = request.form["user_id"]
        print("userrrr: {}".format(user_id))
        public_key, variant = get_user_data(user_id)
        print("variant_selection: {}".format(variant))
        if not public_key:
            return render_template("login.html", 
                                error="User not found")
        
        # Generate random challenge
        challenge = secrets.token_bytes(32)
        # setting of session values
        session["challenge"] = challenge
        session["user_id"] = user_id
        session["variant_selection"] = variant
        # Triggering the next, signing html content 
        # outputting the challenge
        return render_template("login.html", 
                            challenge=challenge.hex(), step="sign")
    if len(session) < 2:
        session["variant_selection"] = crypto.algorithm
    print(session)
    return render_template("login.html", 
                        avg_sign_time=crypto.avg_sign_time)

@app.route("/verify", methods=["POST"])
def verify():
    """
    Handles signature verification querying and logic  with /verify route
    supporting POST only
    """
    user_id = session.get("user_id")
    challenge = session.get("challenge")
    variant = session.get("variant_selection")
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
    public_key, usr_variant = get_user_data(user_id)
    
    # Initialize signature validation with correct variant
    crypto_verify = LatticeCrypto(usr_variant) if variant != \
                                crypto.algorithm else crypto
    if crypto_verify.verify(challenge, signature, public_key):
        session_token = secrets.token_hex(16)

        # 30 seconds expiry for demonstration purposes
        expiry = int(time.time()) + 30
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
        # Removes user's session from database
        delete_session(session_token)
    session.clear()  # Clear Flask session
    remove_files()
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
    usernames = get_all_users()  # Fetch all registered usernames
    return render_template("index.html", 
                            user_id=user_id, usernames=usernames)


@app.route("/variant_selection", methods=["POST"])
def variant_selection():
    """
    Handle user selection of a Dilithium variant.
    """
    
    # Gets the selected variant from the form
    variant = request.form.get("variant_selection", "Auto").strip()
    try:
        # Checks if selected variant is valid and returns error page if not
        if variant != "Auto" and variant not in ["Dilithium2", "Dilithium3", "Dilithium5"]:
            return render_template("login.html", 
                    error="Invalid variant selected. Please choose a valid option.", 
                    current_variant=session.get("variant_selection", "Auto"))
        session["variant_selection"] = variant
        
        # sets the global variable with the correct object initiation based on user preferred
        global crypto
        crypto = LatticeCrypto(variant)
        return redirect(request.referrer or url_for("login"))
    except Exception as e:
        print("Variant selection error: {}".format(e))
        return render_template("login.html", 
                    error="Failed to select variant. Please try again.", 
                    current_variant=session.get("variant_selection", "Auto"))


def remove_files():
    """
    Removes stale Flask session files
    """

    # Builds file path to Flask session files
    folder_path = os.path.join(os.getcwd(), "flask_session")
    
    # Iterates through the files and deletes them
    for filename in os.listdir(folder_path):
        file_path = os.path.join(folder_path, filename)
        if os.path.exists(file_path):
            os.remove(file_path)



if __name__ == "__main__":
    init_db() # Initialises database connection
    remove_files() # remove old flask sessions
    app.run(ssl_context="adhoc", debug=True)  # testingf