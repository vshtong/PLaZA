import sqlite3
import time

def init_db():
    """
    Initialize database with variant column.
    """
    conn = sqlite3.connect("auth.db")
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (user_id TEXT PRIMARY KEY, public_key BLOB, variant TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS sessions
                 (session_token TEXT PRIMARY KEY, user_id TEXT, expiry INTEGER)''')
    conn.commit()
    conn.close()

def user_exists(user_id):
    """
    Check if a user with the given user_id already exists.
    :param:user_id
    """
    conn = sqlite3.connect("auth.db")
    c = conn.cursor()
    c.execute("SELECT 1 FROM users WHERE user_id = ?", (user_id,))
    exists = c.fetchone() is not None
    conn.close()
    return exists

def store_user(user_id, public_key, variant):
    """
    Store user public key and Dilithium variant in database.
    :param:user_id
    :param:public_key
    :param:variant
    """
    conn = sqlite3.connect("auth.db")
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO users (user_id, public_key, variant) VALUES (?, ?, ?)",
              (user_id, public_key, variant))
    conn.commit()
    conn.close()

def get_user_data(user_id):
    """
    Retrieve public key and variant for a user.
    :param:user_id
    """
    conn = sqlite3.connect("auth.db")
    c = conn.cursor()
    c.execute("SELECT public_key, variant FROM users WHERE user_id = ?", (user_id,))
    result = c.fetchone()
    conn.close()
    return result if result else (None, None)

def store_session(session_token, user_id, expiry):
    """
    Store session token.
    :param:session_token
    :param:user_id
    :param:expiry
    """
    conn = sqlite3.connect("auth.db")
    c = conn.cursor()
    c.execute("INSERT INTO sessions (session_token, user_id, expiry) VALUES (?, ?, ?)",
              (session_token, user_id, expiry))
    conn.commit()
    conn.close()

def get_session_user(session_token):
    """
    Retrieve user ID from session token.
    :param:session_token
    """
    conn = sqlite3.connect("auth.db")
    c = conn.cursor()
    c.execute("SELECT user_id FROM sessions WHERE session_token = ? AND expiry > ?",
              (session_token, int(time.time())))
    result = c.fetchone()
    conn.close()
    return result[0] if result else None

def delete_session(session_token):
    """
    Delete a session token from the database.
    :param:session_token
    """
    conn = sqlite3.connect("auth.db")
    c = conn.cursor()
    c.execute("DELETE FROM sessions WHERE session_token = ?", (session_token,))
    conn.commit()
    conn.close()

def get_all_users():
    """
    Returns all user ids from db.
    """
    conn = sqlite3.connect("auth.db")
    c = conn.cursor()
    c.execute("SELECT * FROM users")
    result = c.fetchall()
    conn.close()
    return result

if __name__ == "__main__":
    init_db()
    print(get_all_users()[1])