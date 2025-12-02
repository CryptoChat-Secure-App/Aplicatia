# client_gui.py
# CryptoChat – GUI client pentru server.py (ChaCha20 + Argon2)

import asyncio
import threading
import queue
import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog
import os

import websockets

from crypto_lib import (
    chacha20_encrypt,
    chacha20_decrypt,
    chacha20_load_common_key,
    argon2_hash_password,
    argon2_verify_password,
)

# CONFIG

URI = "wss://chat.cripto-chat.xyz"   # serverul tău prin Cloudflare Tunnel
CHACHA_KEY = chacha20_load_common_key()

# cozi pentru comunicare GUI <-> thread de rețea
to_network: "queue.Queue[tuple]" = queue.Queue()
from_network: "queue.Queue[object]" = queue.Queue()

LOCAL_USERS_FILE = "local_users.txt"

# Argon2 – DEMO local (nu afectează loginul pe server)

def save_local_user_hash(username: str, password: str) -> None:
    try:
        pwd_hash = argon2_hash_password(password)
        with open(LOCAL_USERS_FILE, "a", encoding="utf-8") as f:
            f.write(f"{username}|{pwd_hash}\n")
    except Exception as e:
        print(f"[WARN] Nu am putut salva hash-ul local: {e}")


def check_local_user_password(username: str, password: str) -> None:
    if not os.path.exists(LOCAL_USERS_FILE):
        return
    try:
        with open(LOCAL_USERS_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    u, h = line.split("|", 1)
                except ValueError:
                    continue
                if u == username:
                    ok = argon2_verify_password(h, password)
                    if ok:
                        print("[INFO] Argon2: parola introdusă corespunde hash-ului local.")
                    else:
                        print("[WARN] Argon2: parola introdusă NU corespunde hash-ului local.")
                    return
    except Exception as e:
        print(f"[WARN] Nu am putut verifica parola local: {e}")


# GUI

class ChatGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("CryptoChat – Modern UI")
        self.root.configure(bg="#0f1117")

        self.username: str | None = None

        # pentru contacte
        self.contacts: list[str] = []
        self.active_contact: str | None = None
        # pentru export inbox (user, filename) sau None
        self.pending_inbox_export = None

        self.build_styles()
        self.build_login_frame()
        self.build_chat_frame()
        self.show_login()

        self.root.after(100, self.poll_network_messages)
        self.center_window(880, 580)

    # ---------- stil ----------
    def build_styles(self):
        self.bg = "#0f1117"
        self.panel = "#1a1d25"
        self.accent = "#4dd0e1"
        self.me_color = "#82aaff"
        self.other_color = "#ffcb6b"
        self.text = "#d7dae0"
        self.ts_color = "#8a8f98"

    def center_window(self, w, h):
        ws = self.root.winfo_screenwidth()
        hs = self.root.winfo_screenheight()
        x = (ws // 2) - (w // 2)
        y = (hs // 2) - (h // 2)
        self.root.geometry(f"{w}x{h}+{x}+{y}")

    # ---------- login ----------
    def build_login_frame(self):
        self.login_frame = tk.Frame(self.root, bg=self.bg)

        inner = tk.Frame(self.login_frame, bg=self.bg, padx=20, pady=20)
        inner.place(relx=0.5, rely=0.5, anchor="center")

        title = tk.Label(
            inner,
            text="CryptoChat",
            font=("Segoe UI", 20, "bold"),
            fg=self.accent,
            bg=self.bg
        )
        title.grid(row=0, column=0, columnspan=2, pady=(0, 10))

        tk.Label(inner, text="Username", fg=self.text, bg=self.bg).grid(
            row=1, column=0, sticky="e", padx=(0, 8)
        )
        self.username_entry = tk.Entry(
            inner, width=25, bg=self.panel, fg=self.text, relief="flat"
        )
        self.username_entry.grid(row=1, column=1, pady=5)

        tk.Label(inner, text="Parolă", fg=self.text, bg=self.bg).grid(
            row=2, column=0, sticky="e", padx=(0, 8)
        )
        self.password_entry = tk.Entry(
            inner, width=25, show="*", bg=self.panel, fg=self.text, relief="flat"
        )
        self.password_entry.grid(row=2, column=1, pady=5)

        self.login_status = tk.Label(inner, text="", fg="#888", bg=self.bg)
        self.login_status.grid(row=3, column=0, columnspan=2, pady=5)

        self.btn_register = tk.Button(
            inner,
            text="Register",
            bg=self.panel,
            fg=self.accent,
            width=10,
            relief="flat",
            command=self.on_register,
            activebackground="#232736",
        )
        self.btn_register.grid(row=4, column=0, pady=10, padx=5)

        self.btn_login = tk.Button(
            inner,
            text="Login",
            bg=self.panel,
            fg=self.accent,
            width=10,
            relief="flat",
            command=self.on_login,
            activebackground="#232736",
        )
        self.btn_login.grid(row=4, column=1, pady=10, padx=5)

    def build_chat_frame(self):
        self.chat_frame = tk.Frame(self.root, bg=self.bg, padx=10, pady=10)

        self.lbl_user = tk.Label(
            self.chat_frame,
            text="Neautentificat",
            font=("Segoe UI", 12, "bold"),
            fg=self.accent,
            bg=self.bg
        )
        self.lbl_user.pack(anchor="center", pady=(0, 5))

        # container principal (stânga: contacte, dreapta: chat)
        main = tk.Frame(self.chat_frame, bg=self.bg)
        main.pack(fill="both", expand=True)

        # ---------- panel contacte ----------
        left = tk.Frame(main, bg=self.bg)
        left.pack(side="left", fill="y", padx=(0, 10))

        lbl_contacts = tk.Label(
            left, text="Contacte", fg=self.text, bg=self.bg, font=("Segoe UI", 10, "bold")
        )
        lbl_contacts.pack(anchor="w", pady=(0, 4))

        self.contacts_list = tk.Listbox(
            left,
            height=20,
            width=22,
            bg=self.panel,
            fg=self.text,
            activestyle="none",
            highlightthickness=0,
            selectbackground="#232736",
            selectforeground=self.accent,
        )
        self.contacts_list.pack(fill="y", expand=False)
        self.contacts_list.bind("<<ListboxSelect>>", self.on_contact_select)

        btn_contacts_frame = tk.Frame(left, bg=self.bg)
        btn_contacts_frame.pack(fill="x", pady=(6, 0))

        # Buton ȘTERGE în loc de Reîncarcă
        btn_delete = tk.Button(
            btn_contacts_frame,
            text="Șterge",
            bg=self.panel,
            fg=self.accent,
            relief="flat",
            command=self.on_delete_contact,
            activebackground="#232736",
            width=10,
        )
        btn_delete.pack(side="left", padx=(0, 4))

        btn_add = tk.Button(
            btn_contacts_frame,
            text="Adaugă",
            bg=self.panel,
            fg=self.accent,
            relief="flat",
            command=self.on_add_contact,
            activebackground="#232736",
            width=10,
        )
        btn_add.pack(side="left")

        # panel chat
        right = tk.Frame(main, bg=self.bg)
        right.pack(side="right", fill="both", expand=True)

        self.txt_area = scrolledtext.ScrolledText(
            right,
            width=72,
            height=18,
            fg=self.text,
            bg=self.panel,
            font=("Consolas", 11),
            relief="flat",
            state="disabled"
        )
        self.txt_area.pack(pady=10, fill="both", expand=True)

        self.txt_area.tag_config("me_sender", foreground=self.me_color, font=("Segoe UI", 10, "bold"))
        self.txt_area.tag_config("other_sender", foreground=self.other_color, font=("Segoe UI", 10, "bold"))
        self.txt_area.tag_config("me_text", foreground=self.text)
        self.txt_area.tag_config("other_text", foreground=self.text)
        self.txt_area.tag_config("server_sender", foreground=self.other_color, font=("Segoe UI", 10, "bold"))
        self.txt_area.tag_config("server_text", foreground=self.text)
        self.txt_area.tag_config("ts", foreground=self.ts_color, font=("Consolas", 9, "italic"))

        bottom = tk.Frame(right, bg=self.bg)
        bottom.pack(fill="x", pady=(0, 6))

        bottom.grid_columnconfigure(0, weight=1)
        bottom.grid_columnconfigure(1, weight=0)
        bottom.grid_columnconfigure(2, weight=1)

        tk.Label(bottom, text="Către:", fg=self.text, bg=self.bg).grid(
            row=0, column=0, sticky="e", padx=(0, 8)
        )

        to_wrap = tk.Frame(bottom, bg=self.bg)
        to_wrap.grid(row=0, column=1)
        self.to_entry = tk.Entry(
            to_wrap,
            width=28,
            bg=self.panel,
            fg=self.text,
            relief="flat",
            justify="center",
        )
        self.to_entry.pack()

        inbox_btn = tk.Button(
            bottom,
            text="Inbox",
            bg=self.panel,
            fg=self.accent,
            relief="flat",
            command=self.on_inbox,
            activebackground="#232736",
            width=10,
        )
        inbox_btn.grid(row=0, column=2, padx=8)

        msg_wrap = tk.Frame(bottom, bg=self.bg)
        msg_wrap.grid(row=1, column=1, pady=6)
        self.msg_entry = tk.Entry(
            msg_wrap,
            width=60,
            bg=self.panel,
            fg=self.text,
            relief="flat",
            justify="center",
        )
        self.msg_entry.pack()
        # Enter trimite mesajul
        self.msg_entry.bind("<Return>", self.on_msg_enter)

        send_btn = tk.Button(
            bottom,
            text="Trimite",
            bg=self.panel,
            fg=self.accent,
            relief="flat",
            command=self.on_send,
            activebackground="#232736",
            width=10,
        )
        send_btn.grid(row=1, column=2, padx=8)

        self.status_label = tk.Label(
            self.chat_frame, text="Neconectat", fg="#888", bg=self.bg, anchor="w"
        )
        self.status_label.pack(fill="x", side="bottom")

    # switch
    def show_login(self):
        self.chat_frame.pack_forget()
        self.login_frame.pack(expand=True, fill="both")

    def show_chat(self):
        self.login_frame.pack_forget()
        self.chat_frame.pack(expand=True, fill="both")
        self.msg_entry.focus_set()
        if self.username:
            self.lbl_user.config(text=f"Logat ca: {self.username}")

    # acțiuni login/register
    def on_register(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        if not username or not password:
            messagebox.showwarning("Eroare", "Completează username și parolă.")
            return

        save_local_user_hash(username, password)

        self.login_status.config(text="Trimit înregistrare la server...", fg=self.accent)
        to_network.put(("REGISTER", (username, password)))

    def on_login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        if not username or not password:
            messagebox.showwarning("Eroare", "Completează username și parolă.")
            return

        check_local_user_password(username, password)

        self.login_status.config(text="Trimit login la server...", fg=self.accent)
        self.username = username
        to_network.put(("LOGIN", (username, password)))

    # acțiuni chat
    def on_msg_enter(self, event):
        """Trimite mesajul când se apasă Enter în câmpul de mesaj."""
        self.on_send()
        return "break"

    def on_send(self):
        if not self.username:
            messagebox.showwarning("Eroare", "Nu ești logat.")
            return

        to_user = self.to_entry.get().strip()
        if not to_user and self.active_contact:
            to_user = self.active_contact

        text = self.msg_entry.get().strip()
        if not to_user or not text:
            return

        # dacă nu este deja în lista de contacte, îl adăugăm automat
        if to_user not in self.contacts:
            to_network.put(("ADD_CONTACT", to_user))
            self.set_status(f"Contactul '{to_user}' a fost adăugat automat.", "#4dd0e1")

        to_network.put(("MSG", (to_user, text)))
        self.append_bubble(f"TU → {to_user}", text, me=True, ts=None)
        self.msg_entry.delete(0, tk.END)

    def on_inbox(self):
        if not self.username:
            return

        # determinăm contactul curent (din selecție sau din câmpul "Către")
        target = self.active_contact or self.to_entry.get().strip()
        if not target:
            messagebox.showwarning("Inbox", "Selectează un contact sau completează câmpul 'Către'.")
            return

        # pregătim exportul pentru conversația cu acest contact
        filename = f"inbox_{self.username}_{target}.txt"
        self.pending_inbox_export = (target, filename)

        # cerem istoricul conversației cu acest contact
        to_network.put(("HISTORY", target))
        self.set_status(f"Export inbox pentru {target} în {filename}...", "#999")

    # contacte
    def on_add_contact(self):
        if not self.username:
            messagebox.showwarning("Eroare", "Trebuie să fii logat pentru a adăuga contacte.")
            return
        name = simpledialog.askstring("Adaugă contact", "Username contact:")
        if not name:
            return
        name = name.strip()
        if not name:
            return
        to_network.put(("ADD_CONTACT", name))
        self.set_status(f"Trimit cerere de adăugare contact ({name})...", "#999")

    def on_delete_contact(self):
        if not self.username:
            messagebox.showwarning("Eroare", "Trebuie să fii logat pentru a șterge contacte.")
            return

        sel = self.contacts_list.curselection()
        if not sel:
            messagebox.showwarning("Eroare", "Selectează un contact de șters.")
            return

        contact = self.contacts_list.get(sel[0])

        # eliminăm local din listă
        self.contacts = [c for c in self.contacts if c != contact]
        self.update_contacts_list(self.contacts)
        if self.active_contact == contact:
            self.active_contact = None
            self.to_entry.delete(0, tk.END)

        # trimitem și la server
        to_network.put(("DEL_CONTACT", contact))
        self.set_status(f"Am trimis cerere de ștergere pentru contactul {contact}.", "#999")

    def on_contact_select(self, event):
        if not self.contacts_list.curselection():
            return
        idx = self.contacts_list.curselection()[0]
        contact = self.contacts_list.get(idx)
        self.active_contact = contact

        # curățăm fereastra de chat pentru a afișa DOAR conversația cu acest contact
        self.txt_area.configure(state="normal")
        self.txt_area.delete(1.0, tk.END)
        self.txt_area.configure(state="disabled")

        self.to_entry.delete(0, tk.END)
        self.to_entry.insert(0, contact)

        # cerem istoricul pentru contactul selectat
        to_network.put(("HISTORY", contact))
        self.set_status(f"Afișez doar istoricul cu {contact}...", "#999")

    # utilitare / output
    def append_bubble(self, sender, text, me=False, server=False, ts: str | None = None):
        indent = " " * (10 if me else 2)
        if server:
            sender_tag = "server_sender"
            text_tag = "server_text"
        else:
            sender_tag = "me_sender" if me else "other_sender"
            text_tag = "me_text" if me else "other_text"

        self.txt_area.configure(state="normal")
        self.txt_area.insert(tk.END, f"{indent}{sender}\n", sender_tag)
        if ts:
            self.txt_area.insert(tk.END, f"{indent}{ts}\n", "ts")
        self.txt_area.insert(tk.END, f"{indent}{text}\n\n", text_tag)
        self.txt_area.configure(state="disabled")
        self.txt_area.see(tk.END)

    def set_status(self, text, color=None):
        self.status_label.config(text=text, fg=color or "#888")

    def update_contacts_list(self, contacts: list[str]):
        self.contacts = contacts
        self.contacts_list.delete(0, tk.END)
        for c in contacts:
            self.contacts_list.insert(tk.END, c)

    def show_history_for(self, user: str, items: list[tuple]):
        # doar afișăm la finalul chatului istoric marcat clar
        self.append_bubble("SERVER", f"=== Istoric cu {user} ===", server=True)
        for created_at, sender, text in items:
            me = sender == self.username
            self.append_bubble(f"[History] {sender}", text, me=me, server=False, ts=created_at)

    def poll_network_messages(self):
        try:
            while True:
                msg = from_network.get_nowait()

                if isinstance(msg, str):
                    # mesaje de control
                    if msg == "__SWITCH_TO_CHAT__":
                        self.show_chat()
                        self.set_status("Conectat la server.", "#4dd0e1")
                        continue

                    if msg.startswith("__LOGIN_OK__"):
                        self.login_status.config(text="Login reușit!", fg="green")
                        # la login putem să cerem direct contactele
                        to_network.put(("CONTACTS", None))
                        continue

                    if msg.startswith("__LOGIN_FAIL__"):
                        reason = msg.split(":", 1)[1]
                        self.login_status.config(text=f"Login eșuat: {reason}", fg="red")
                        self.username = None
                        continue

                    if msg.startswith("__REGISTER_OK__"):
                        self.login_status.config(text="Înregistrare reușită.", fg="green")
                        continue

                    if msg.startswith("__REGISTER_FAIL__"):
                        reason = msg.split(":", 1)[1]
                        self.login_status.config(text=f"Înregistrare eșuată: {reason}", fg="red")
                        continue

                    # orice alt text simplu -> bubble de la server
                    self.append_bubble("SERVER", msg, server=True)
                    continue

                if isinstance(msg, tuple):
                    kind = msg[0]

                    if kind == "CHAT":
                        _, s, r, text = msg
                        self.append_bubble(f"{s} → {r}", text, me=(s == self.username))
                        continue

                    if kind == "INBOX_ITEM":
                        _, created_at, s, r, text = msg
                        self.append_bubble(f"[Inbox] {s} → {r}", text, me=False, ts=created_at)
                        continue

                    if kind == "RAW":
                        _, text = msg
                        self.append_bubble("SERVER", text, server=True)
                        continue

                    if kind == "CONTACTS":
                        _, contacts = msg
                        self.update_contacts_list(contacts)
                        self.set_status(f"{len(contacts)} contacte încărcate.", "#4dd0e1")
                        continue

                    if kind == "HISTORY":
                        _, user, items = msg
                        # afișăm istoricul în fereastra de chat
                        self.show_history_for(user, items)

                        # dacă avem un export de inbox în așteptare pentru acest user, salvăm în fișier
                        if self.pending_inbox_export and self.pending_inbox_export[0] == user:
                            filename = self.pending_inbox_export[1]
                            try:
                                with open(filename, "w", encoding="utf-8") as f:
                                    for created_at, sender, text in items:
                                        f.write(f"[{created_at}] {sender}: {text}\n")
                                messagebox.showinfo("Inbox", f"Inbox salvat în: {filename}")
                            except Exception as e:
                                messagebox.showerror("Inbox", f"Eroare la salvare: {e}")
                            self.pending_inbox_export = None
                        continue

        except queue.Empty:
            pass

        self.root.after(100, self.poll_network_messages)

# THREAD DE REȚEA

async def net_sender(ws: websockets.WebSocketClientProtocol):
    loop = asyncio.get_running_loop()
    while True:
        cmd, payload = await loop.run_in_executor(None, to_network.get)

        if cmd == "REGISTER":
            username, password = payload
            line = f"REGISTER|{username}|{password}"
            await ws.send(line)

        elif cmd == "LOGIN":
            username, password = payload
            line = f"LOGIN|{username}|{password}"
            await ws.send(line)

        elif cmd == "MSG":
            to_user, text = payload
            try:
                ciphertext = chacha20_encrypt(CHACHA_KEY, text)
            except Exception as e:
                from_network.put(("RAW", f"[NET] Eroare criptare, trimit necriptat: {e}"))
                ciphertext = text
            line = f"MSG|{to_user}|{ciphertext}"
            await ws.send(line)

        elif cmd == "INBOX":
            await ws.send("INBOX")

        elif cmd == "CONTACTS":
            await ws.send("CONTACTS")

        elif cmd == "ADD_CONTACT":
            target = payload
            line = f"ADD_CONTACT|{target}"
            await ws.send(line)

        elif cmd == "DEL_CONTACT":
            target = payload
            line = f"DEL_CONTACT|{target}"
            await ws.send(line)

        elif cmd == "HISTORY":
            with_user = payload
            line = f"HISTORY|{with_user}"
            await ws.send(line)


async def net_receiver(ws: websockets.WebSocketClientProtocol):
    contacts_tmp: list[str] = []
    history_tmp: list[tuple] = []
    history_user: str | None = None

    async for raw in ws:
        msg = raw.strip()

        if msg == "HELLO_CLIENT":
            # handshake, ignorăm
            continue

        # răspunsuri de protocol login/register
        if msg.startswith("INFO|LOGIN_OK"):
            from_network.put("__LOGIN_OK__")
            from_network.put("__SWITCH_TO_CHAT__")
            continue

        if msg.startswith("ERR|BAD_PASSWORD"):
            from_network.put("__LOGIN_FAIL__:Parolă greșită.")
            continue

        if msg.startswith("ERR|NO_SUCH_USER"):
            from_network.put("__LOGIN_FAIL__:Nu există acest utilizator.")
            continue

        if msg.startswith("INFO|REGISTER_OK"):
            from_network.put("__REGISTER_OK__")
            continue

        if msg.startswith("ERR|USERNAME_EXISTS"):
            from_network.put("__REGISTER_FAIL__:Username deja folosit.")
            continue

        # inbox
        if msg == "INFO|INBOX_BEGIN":
            from_network.put(("RAW", "=== INBOX ==="))
            continue
        if msg == "INFO|INBOX_END":
            from_network.put(("RAW", "=== SFÂRȘIT INBOX ==="))
            continue
        if msg.startswith("INBOX_ITEM|"):
            try:
                _, created_at, s, r, text = msg.split("|", 4)
            except ValueError:
                from_network.put(("RAW", msg))
                continue

            try:
                decrypted_text = chacha20_decrypt(CHACHA_KEY, text)
            except Exception:
                decrypted_text = text

            from_network.put(("INBOX_ITEM", created_at, s, r, decrypted_text))
            continue

        # mesaj realtime
        if msg.startswith("MSG|"):
            parts = msg.split("|", 3)
            if len(parts) == 4:
                _, s, r, text = parts
                try:
                    decrypted_text = chacha20_decrypt(CHACHA_KEY, text)
                except Exception:
                    decrypted_text = text
                from_network.put(("CHAT", s, r, decrypted_text))
                continue

        # contacte
        if msg == "CONTACTS_BEGIN":
            contacts_tmp = []
            continue

        if msg.startswith("CONTACT|"):
            try:
                _, uname = msg.split("|", 1)
            except ValueError:
                continue
            contacts_tmp.append(uname)
            continue

        if msg == "CONTACTS_END":
            from_network.put(("CONTACTS", contacts_tmp))
            contacts_tmp = []
            continue

        # istoric conversație
        if msg.startswith("HISTORY_BEGIN|"):
            try:
                _, history_user = msg.split("|", 1)
            except ValueError:
                history_user = None
            history_tmp = []
            continue

        if msg.startswith("HISTORY_ITEM|"):
            try:
                _, u, created_at, s, text = msg.split("|", 4)
            except ValueError:
                from_network.put(("RAW", msg))
                continue
            try:
                decrypted_text = chacha20_decrypt(CHACHA_KEY, text)
            except Exception:
                decrypted_text = text
            history_tmp.append((created_at, s, decrypted_text))
            continue

        if msg.startswith("HISTORY_END|"):
            if history_user is not None:
                from_network.put(("HISTORY", history_user, history_tmp))
            history_user = None
            history_tmp = []
            continue

        # altceva
        from_network.put(("RAW", msg))


async def network_loop():
    while True:
        try:
            async with websockets.connect(
                URI,
                ping_interval=None,
                ping_timeout=None,
            ) as ws:
                from_network.put("[NET] Conectat la server.")
                recv_task = asyncio.create_task(net_receiver(ws))
                send_task = asyncio.create_task(net_sender(ws))

                done, pending = await asyncio.wait(
                    {recv_task, send_task},
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for t in pending:
                    t.cancel()
        except Exception as e:
            from_network.put(f"[NET] Eroare conexiune: {e}, reîncerc în 3 secunde...")
            await asyncio.sleep(3)


def start_network_thread():
    def runner():
        asyncio.run(network_loop())
    th = threading.Thread(target=runner, daemon=True)
    th.start()

# ENTRYPOINT

if __name__ == "__main__":
    start_network_thread()
    root = tk.Tk()
    app = ChatGUI(root)
    root.mainloop()
