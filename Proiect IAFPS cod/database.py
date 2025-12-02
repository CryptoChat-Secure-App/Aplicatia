# database.py – SQLite pentru utilizatori, parole, contacte și mesaje

import sqlite3
from typing import Tuple, List

from crypto_lib import argon2_hash_password, argon2_verify_password

DB_FILE = "chat.db"


def get_conn():
    return sqlite3.connect(DB_FILE)


# INITIALIZARE Baza de date (UTILIZATORI + PAROLE + CONTACTE + MESAJ ISTORIC)
def init_db():
    conn = get_conn()
    cur = conn.cursor()

    # UTILIZATORI (CU PAROLĂ HASHUITĂ ARGON2)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            pwd_hash TEXT NOT NULL
        )
        """
    )

    # CONTACTE (LISTĂ DE PRIETENI)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS contacts (
            user_id INTEGER NOT NULL,
            contact_username TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        """
    )

    # ISTORIC MESAJE (CRIPATE)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            ciphertext TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(sender_id) REFERENCES users(id),
            FOREIGN KEY(receiver_id) REFERENCES users(id)
        )
        """
    )

    conn.commit()
    conn.close()


#               UTILIZATORI (REGISTER + LOGIN)

def _get_user_id(cur, username: str):
    cur.execute("SELECT id FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    return row[0] if row else None


def register_user(username: str, password: str) -> Tuple[bool, str]:
    conn = get_conn()
    cur = conn.cursor()
    try:
        pwd_hash = argon2_hash_password(password)
        cur.execute(
            "INSERT INTO users (username, pwd_hash) VALUES (?, ?)",
            (username, pwd_hash),
        )
        conn.commit()
        return True, "OK"
    except sqlite3.IntegrityError:
        return False, "USERNAME_EXISTS"
    except Exception as e:
        return False, f"DB_ERROR:{e}"
    finally:
        conn.close()


def authenticate_user(username: str, password: str):
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT id, pwd_hash FROM users WHERE username = ?", (username,)
        )
        row = cur.fetchone()
        if not row:
            return False, None, "NO_SUCH_USER"
        user_id, pwd_hash = row
        if argon2_verify_password(pwd_hash, password):
            return True, user_id, "LOGIN_OK"
        else:
            return False, None, "BAD_PASSWORD"
    except Exception as e:
        return False, None, f"DB_ERROR:{e}"
    finally:
        conn.close()


#                CONTACTE (ADD + GET + DELETE)

def get_contacts(username: str) -> List[str]:
    conn = get_conn()
    cur = conn.cursor()

    # aflăm ID
    cur.execute("SELECT id FROM users WHERE username = ?", (username,))
    row = cur.fetchone()

    if not row:
        conn.close()
        return []

    user_id = row[0]

    # scoatem lista de contacte
    cur.execute(
        "SELECT contact_username FROM contacts WHERE user_id = ?", (user_id,)
    )
    contacts = [r[0] for r in cur.fetchall()]

    conn.close()
    return contacts


def add_contact(username: str, contact_username: str) -> Tuple[bool, str]:
    conn = get_conn()
    cur = conn.cursor()
    try:
        # 1. aflăm user_id al proprietarului listei de contacte
        cur.execute("SELECT id FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        if not row:
            return False, "NO_SUCH_USER"
        user_id = row[0]

        # 2. verificăm dacă există utilizatorul pe care vrem să-l adăugăm
        cur.execute("SELECT username FROM users WHERE username = ?", (contact_username,))
        row = cur.fetchone()
        if not row:
            return False, "NO_SUCH_CONTACT"
        real_contact_username = row[0]

        # 3. verificăm dacă deja există în listă
        cur.execute(
            """
            SELECT 1 FROM contacts
            WHERE user_id = ? AND contact_username = ?
            """,
            (user_id, real_contact_username),
        )

        if cur.fetchone():
            return True, "ALREADY_EXISTS"

        # 4. adăugăm contactul
        cur.execute(
            """
            INSERT INTO contacts (user_id, contact_username)
            VALUES (?, ?)
            """,
            (user_id, real_contact_username),
        )
        conn.commit()
        return True, "OK"

    except Exception as e:
        return False, f"DB_ERROR:{e}"
    finally:
        conn.close()


def delete_contact(username: str, contact_username: str) -> Tuple[bool, str]:
    """Șterge un contact din lista utilizatorului (dacă există)."""
    conn = get_conn()
    cur = conn.cursor()
    try:
        # aflăm user_id al proprietarului
        cur.execute("SELECT id FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        if not row:
            return False, "NO_SUCH_USER"
        user_id = row[0]

        # ștergem contactul
        cur.execute(
            """
            DELETE FROM contacts
            WHERE user_id = ? AND contact_username = ?
            """,
            (user_id, contact_username),
        )
        if cur.rowcount == 0:
            conn.commit()
            return False, "NOT_FOUND"

        conn.commit()
        return True, "OK"

    except Exception as e:
        return False, f"DB_ERROR:{e}"
    finally:
        conn.close()

# MESAJ ISTORIC (SAVE + GET)

def save_message(
    sender_username: str, receiver_username: str, ciphertext: str
) -> Tuple[bool, str]:
    conn = get_conn()
    cur = conn.cursor()
    try:
        sender_id = _get_user_id(cur, sender_username)
        receiver_id = _get_user_id(cur, receiver_username)

        if sender_id is None or receiver_id is None:
            return False, "NO_SUCH_USER"

        cur.execute(
            """
            INSERT INTO messages (sender_id, receiver_id, ciphertext)
            VALUES (?, ?, ?)
            """,
            (sender_id, receiver_id, ciphertext),
        )

        conn.commit()
        return True, "OK"

    except Exception as e:
        return False, f"DB_ERROR:{e}"

    finally:
        conn.close()


def get_inbox_for_user(username: str) -> List[tuple]:
    """Returnează lista de mesaje primite de user."""
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT m.created_at, su.username, ru.username, m.ciphertext
            FROM messages m
            JOIN users su ON m.sender_id = su.id
            JOIN users ru ON m.receiver_id = ru.id
            WHERE ru.username = ?
            ORDER BY m.created_at ASC
            """,
            (username,),
        )
        return cur.fetchall()
    except Exception:
        return []
    finally:
        conn.close()


def get_message_history(user1: str, user2: str) -> List[tuple]:
    """Returnează [(sender_username, ciphertext, timestamp), ...] conversații în ambele direcții."""
    conn = get_conn()
    cur = conn.cursor()

    try:
        cur.execute(
            """
            SELECT su.username AS sender,
                   m.ciphertext,
                   m.created_at
            FROM messages m
            JOIN users su ON su.id = m.sender_id
            JOIN users ru ON ru.id = m.receiver_id
            WHERE (su.username = ? AND ru.username = ?)
               OR (su.username = ? AND ru.username = ?)
            ORDER BY m.created_at ASC
            """,
            (user1, user2, user2, user1),
        )

        return cur.fetchall()

    except Exception:
        return []

    finally:
        conn.close()
