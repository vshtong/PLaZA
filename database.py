import sqlite3
import time


def init_db():
    """
    Initialise database with "users" and "sessions" tables.
    """

    conn = sqlite3.connect("auth.db")
    c = conn.cursor()

    # Creates a table named "users" with columns "user_id",
    # "public_key", and "variant" if doesnt already exist
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (user_id TEXT PRIMARY KEY, 
                 public_key BLOB, 
                 variant TEXT)''')
    
    # Creates a table named "sessions" with 
    # columns "session_token", "user_id", 
    # "expiry" if doesnt already exist
    c.execute('''CREATE TABLE IF NOT EXISTS sessions
                 (session_token TEXT PRIMARY KEY, 
                 user_id TEXT, 
                 expiry INTEGER)''')
    
    # Commits and closes connection
    conn.commit()
    conn.close()

def user_exists(user_id):
    """--
    Check if a user with the given user_id already exists.
    :param:user_id
    :return: boolean
        True if user exists
    """
    conn = sqlite3.connect("auth.db")
    c = conn.cursor()
    
    # Validate if user exists exists in the database
    c.execute("SELECT 1 FROM users WHERE \
                user_id = ?", (user_id,))
    
    # return true condition if user exists
    exists = c.fetchone() is not None
    conn.close()
    return exists

def store_user(user_id, public_key, variant):
    """
    Store user id, public key and selected Dilithium 
    variant in database.
    :param:user_id
    :param:public_key
    :param:variant
    """

    # This opens a connection to the "auth" database 
    # in directory
    conn = sqlite3.connect("auth.db")
    c = conn.cursor()

    # Executes query to register the id, public key 
    # and variant of a new user.
    c.execute("INSERT OR REPLACE INTO users (user_id, \
                    public_key, variant) VALUES (?, ?, ?)",
              (user_id, public_key, variant))
    
    conn.commit()
    conn.close()

def get_user_data(user_id):
    """--
    Retrieve public key and variant for a user.
    :param:user_id
    """

    conn = sqlite3.connect("auth.db")
    c = conn.cursor()

    # Executes query to get the public_key and variant
    # of user.
    c.execute("SELECT public_key, variant FROM users \
              WHERE user_id = ?", (user_id,))
    result = c.fetchone()
    conn.close()

    # if no match found, return none types
    return result if result else (None, None)

def store_session(session_token, user_id, expiry):
    """--
    Store session token.
    :param:session_token
    :param:user_id
    :param:expiry
    """

    # This opens a connection to the "auth" database 
    # in directory
    conn = sqlite3.connect("auth.db")
    c = conn.cursor()

    # Executes the query to store the session_token, 
    # user_id key and expiry of a new user.
    c.execute("INSERT INTO sessions (session_token, \
                    user_id, expiry) VALUES (?, ?, ?)",
              (session_token, user_id, expiry))
    conn.commit()
    conn.close()

def get_session_user(session_token):
    """--
    Retrieve user ID from session token.
    :param:session_token
    :return:user_id
    """
    conn = sqlite3.connect("auth.db")
    c = conn.cursor()

    # Get user id from session token
    c.execute("SELECT user_id FROM sessions WHERE \
                    session_token = ? AND expiry > ?",
              (session_token, int(time.time())))
    result = c.fetchone()
    conn.close()

    # Return user_id if exists, otherwise return None type
    return result[0] if result else None

def delete_session(session_token):
    """--
    Delete a session token from the database.
    :param:session_token
    """
    conn = sqlite3.connect("auth.db")
    c = conn.cursor()

    # Executes the query to delete user session 
    # from database
    c.execute("DELETE FROM sessions WHERE \
              session_token = ?", (session_token,))
    conn.commit()
    conn.close()

def get_all_users():
    """
    Returns all user ids and variants from db.
    """
    conn = sqlite3.connect("auth.db")
    c = conn.cursor()

    # Get all user ids with their respective variants
    c.execute("SELECT user_id, variant FROM users")
    result = c.fetchall()
    conn.close()
    return result

if __name__ == "__main__":
    init_db()
    print(get_all_users())