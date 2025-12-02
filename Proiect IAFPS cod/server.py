# server.py – WebSocket server pentru CryptoChat (ChaCha20 + Argon2 + SQLite)

import asyncio
import datetime
import os
from collections import deque, defaultdict
from typing import Dict, Any

import websockets
from websockets.server import WebSocketServerProtocol

from crypto_lib import chacha20_load_common_key
from database import (
    init_db,
    register_user,
    authenticate_user,
    save_message,
    get_inbox_for_user,
    get_contacts,
    add_contact,
    get_message_history,
    delete_contact,
)

# CONFIG / GLOBALE

CHACHA_KEY = chacha20_load_common_key()  # aceeași cheie trebuie copiată la clienți

# ws -> info (username, ip)
clients: Dict[WebSocketServerProtocol, Dict[str, Any]] = {}
# username -> ws
user_sockets: Dict[str, WebSocketServerProtocol] = {}

# rate limit & ban
RATE_WINDOW_SEC = 5
RATE_MAX_MSG = 8          # mai multe mesaje în 5 secunde => spam
BAN_THRESHOLD = 3         # de câte ori depășește limita până la ban
BAN_DURATION_SEC = 60

ip_events: Dict[str, deque] = defaultdict(deque)      # ip -> deque[timestamps]
ip_offenses: Dict[str, int] = defaultdict(int)        # ip -> număr depășiri
banned_ips: Dict[str, float] = {}                     # ip -> unix_time_expire

# logging
LOG_FILE = "server.log"
MAX_LOG_SIZE = 200_000  # bytes


def log_event(msg: str) -> None:
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}\n"
    print(line, end="")
    # file log
    try:
        rotate = os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > MAX_LOG_SIZE
        if rotate:
            ts_short = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            os.rename(LOG_FILE, f"server_{ts_short}.log")
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        pass


# Rate limit / ban

def check_rate_and_ban(ip: str) -> bool:
    """
    Actualizează info de rate-limit și ban pentru IP.
    Returnează True dacă IP-ul ESTE banat (nu mai acceptăm comenzi).
    """
    now = datetime.datetime.now().timestamp()

    # verificăm dacă e deja banat
    if ip in banned_ips:
        if now < banned_ips[ip]:
            return True
        else:
            # ban expirat
            del banned_ips[ip]

    # actualizăm lista de evenimente
    dq = ip_events[ip]
    dq.append(now)
    # păstrăm doar ultimii RATE_WINDOW_SEC
    while dq and now - dq[0] > RATE_WINDOW_SEC:
        dq.popleft()

    if len(dq) > RATE_MAX_MSG:
        ip_offenses[ip] += 1
        log_event(f"[RATE_LIMIT] IP {ip} a trimis {len(dq)} mesaje în {RATE_WINDOW_SEC}s (ofense={ip_offenses[ip]})")
        # dacă a depășit de mai multe ori, îl banăm
        if ip_offenses[ip] >= BAN_THRESHOLD:
            banned_ips[ip] = now + BAN_DURATION_SEC
            log_event(f"[IP_BAN] IP {ip} banat pentru {BAN_DURATION_SEC}s")
        # oricum considerăm acest mesaj ca „blocabil”, deci întoarcem True
        return True

    return False

# Utilitare conexiune

def extract_ip(ws: WebSocketServerProtocol) -> str:
    h = ws.request_headers
    ip = h.get("CF-Connecting-IP") or h.get("X-Forwarded-For")
    if not ip:
        ra = ws.remote_address
        if isinstance(ra, tuple) and len(ra) >= 1:
            ip = ra[0]
    return ip or "necunoscut"


async def send_safe(ws: WebSocketServerProtocol, text: str):
    try:
        await ws.send(text)
    except Exception as e:
        log_event(f"[WARN] Nu pot trimite către client: {e}")


# Handler per client (comenzi text)

async def handle_command(ws: WebSocketServerProtocol, msg: str):
    info = clients.get(ws, {})
    ip = info.get("ip", "necunoscut")
    username = info.get("username")

    # rate limit & ban: dacă returnează True => ignorăm mesajul
    if check_rate_and_ban(ip):
        await send_safe(ws, "ERR|RATE_LIMIT")
        return

    if not msg:
        return

    parts = msg.split("|")
    cmd = parts[0].upper()

    # REGISTER
    if cmd == "REGISTER" and len(parts) == 3:
        user, pwd = parts[1].strip(), parts[2]
        ok, code = register_user(user, pwd)
        if ok:
            await send_safe(ws, "INFO|REGISTER_OK")
            log_event(f"[REGISTER_OK] user={user} ip={ip}")
        else:
            if code == "USERNAME_EXISTS":
                await send_safe(ws, "ERR|USERNAME_EXISTS")
            else:
                await send_safe(ws, f"ERR|{code}")
            log_event(f"[REGISTER_FAIL] user={user} ip={ip} code={code}")
        return

    # LOGIN
    if cmd == "LOGIN" and len(parts) == 3:
        user, pwd = parts[1].strip(), parts[2]
        ok, user_id, code = authenticate_user(user, pwd)
        if ok:
            info["username"] = user
            info["user_id"] = user_id
            clients[ws] = info
            user_sockets[user] = ws
            await send_safe(ws, "INFO|LOGIN_OK")
            log_event(f"[LOGIN_OK] user={user} id={user_id} ip={ip}")
        else:
            if code == "NO_SUCH_USER":
                await send_safe(ws, "ERR|NO_SUCH_USER")
            elif code == "BAD_PASSWORD":
                await send_safe(ws, "ERR|BAD_PASSWORD")
            else:
                await send_safe(ws, f"ERR|{code}")
            log_event(f"[LOGIN_FAIL] user={user} ip={ip} code={code}")
        return

    # INBOX (mesaje primite de user)
    if cmd == "INBOX":
        if not username:
            await send_safe(ws, "ERR|NOT_LOGGED_IN")
            return
        rows = get_inbox_for_user(username)
        await send_safe(ws, "INFO|INBOX_BEGIN")
        for created_at, s, r, ciphertext in rows:
            # serverul nu decriptează nimic, trimite brut
            line = f"INBOX_ITEM|{created_at}|{s}|{r}|{ciphertext}"
            await send_safe(ws, line)
        await send_safe(ws, "INFO|INBOX_END")
        log_event(f"[INBOX] user={username} ip={ip} count={len(rows)}")
        return

    # MSG (mesaj one-to-one)
    if cmd == "MSG" and len(parts) >= 3:
        if not username:
            await send_safe(ws, "ERR|NOT_LOGGED_IN")
            return

        to_user = parts[1].strip()
        ciphertext = "|".join(parts[2:])  # textul poate conține '|'

        # salvăm în DB
        ok, code = save_message(username, to_user, ciphertext)
        if not ok:
            await send_safe(ws, f"ERR|{code}")
            log_event(f"[MSG_DB_FAIL] {username}->{to_user} ip={ip} code={code}")
            return

        # livrăm în timp real dacă destinatarul este conectat
        dest_ws = user_sockets.get(to_user)
        if dest_ws is not None and dest_ws.open:
            line = f"MSG|{username}|{to_user}|{ciphertext}"
            await send_safe(dest_ws, line)
            await send_safe(ws, "INFO|MSG_DELIVERED")
            log_event(f"[MSG_RT] {username}->{to_user} ip={ip}")
        else:
            await send_safe(ws, "INFO|MSG_STORED_OFFLINE")
            log_event(f"[MSG_OFFLINE] {username}->{to_user} ip={ip}")
        return

    # CONTACTS – cere lista de contacte
    if cmd == "CONTACTS":
        if not username:
            await send_safe(ws, "ERR|NOT_LOGGED_IN")
            return
        contact_list = get_contacts(username)
        await send_safe(ws, "CONTACTS_BEGIN")
        for c in contact_list:
            await send_safe(ws, f"CONTACT|{c}")
        await send_safe(ws, "CONTACTS_END")
        log_event(f"[CONTACTS] user={username} ip={ip} count={len(contact_list)}")
        return

    # ADD_CONTACT – adaugă un contact
    if cmd == "ADD_CONTACT" and len(parts) == 2:
        if not username:
            await send_safe(ws, "ERR|NOT_LOGGED_IN")
            return
        target = parts[1].strip()
        ok, code = add_contact(username, target)
        if ok:
            await send_safe(ws, "INFO|ADD_CONTACT_OK")
            # putem retrimite lista actualizată
            contact_list = get_contacts(username)
            await send_safe(ws, "CONTACTS_BEGIN")
            for c in contact_list:
                await send_safe(ws, f"CONTACT|{c}")
            await send_safe(ws, "CONTACTS_END")
            log_event(f"[ADD_CONTACT_OK] user={username} added={target} ip={ip}")
        else:
            await send_safe(ws, f"ERR|ADD_CONTACT|{code}")
            log_event(f"[ADD_CONTACT_FAIL] user={username} target={target} ip={ip} code={code}")
        return

    # DEL_CONTACT – șterge un contact
    if cmd == "DEL_CONTACT" and len(parts) == 2:
        if not username:
            await send_safe(ws, "ERR|NOT_LOGGED_IN")
            return
        target = parts[1].strip()
        ok, code = delete_contact(username, target)
        if ok:
            await send_safe(ws, "INFO|DEL_CONTACT_OK")
            # retrimitem lista actualizată
            contact_list = get_contacts(username)
            await send_safe(ws, "CONTACTS_BEGIN")
            for c in contact_list:
                await send_safe(ws, f"CONTACT|{c}")
            await send_safe(ws, "CONTACTS_END")
            log_event(f"[DEL_CONTACT_OK] user={username} deleted={target} ip={ip}")
        else:
            await send_safe(ws, f"ERR|DEL_CONTACT|{code}")
            log_event(f"[DEL_CONTACT_FAIL] user={username} target={target} ip={ip} code={code}")
        return

    # HISTORY – istoric conversație cu un user
    if cmd == "HISTORY" and len(parts) == 2:
        if not username:
            await send_safe(ws, "ERR|NOT_LOGGED_IN")
            return
        with_user = parts[1].strip()
        rows = get_message_history(username, with_user)
        await send_safe(ws, f"HISTORY_BEGIN|{with_user}")
        for sender, ciphertext, created_at in rows:
            # nu decriptăm pe server, trimitem ciphertext brut
            line = f"HISTORY_ITEM|{with_user}|{created_at}|{sender}|{ciphertext}"
            await send_safe(ws, line)
        await send_safe(ws, f"HISTORY_END|{with_user}")
        log_event(f"[HISTORY] user={username} with={with_user} ip={ip} count={len(rows)}")
        return

    # Necunoscut
    await send_safe(ws, "ERR|BAD_COMMAND")


async def client_handler(ws: WebSocketServerProtocol, path: str):
    ip = extract_ip(ws)

    # verificăm dacă IP-ul este deja banat
    if check_rate_and_ban(ip):
        await send_safe(ws, "ERR|IP_BANNED")
        await ws.close()
        return

    log_event(f"[CONN_OPEN] ip={ip} raw={ws.remote_address}")

    clients[ws] = {"ip": ip, "username": None, "user_id": None}

    try:
        await send_safe(ws, "HELLO_CLIENT")
        async for raw in ws:
            msg = raw.strip()
            await handle_command(ws, msg)
    except websockets.ConnectionClosed:
        pass
    except Exception as e:
        log_event(f"[ERR_CONN] ip={ip} err={e}")
    finally:
        info = clients.get(ws, {})
        user = info.get("username")
        if user and user_sockets.get(user) is ws:
            del user_sockets[user]
        clients.pop(ws, None)
        log_event(f"[CONN_CLOSE] ip={ip} user={user}")


# MAIN

async def main():
    init_db()
    host = "0.0.0.0"
    port = 5000
    log_event(f"[SERVER_START] ws://{host}:{port}")
    async with websockets.serve(
        client_handler,
        host,
        port,
        ping_interval=None,
        ping_timeout=None,
        max_size=2**25
    ):
        await asyncio.Future()  # rulează la infinit


if __name__ == "__main__":
    asyncio.run(main())
