# 💬 CryptoChat - Secure Messaging Application

**CryptoChat** este o aplicație de mesagerie instantanee dezvoltată în **Python**, proiectată pentru a asigura confidențialitatea, integritatea și disponibilitatea datelor. Proiectul implementează o arhitectură **Client-Server** asincronă, garantând criptarea **End-to-End (E2EE)** a tuturor conversațiilor.

Aplicația este construită modular, separând logica de rețea, criptografia, baza de date și interfața grafică.

---

## 🚀 Funcționalități Cheie

### 🛡️ Securitate și Criptografie
* **Criptare E2EE:** Mesajele sunt criptate local pe dispozitivul clientului folosind algoritmul **ChaCha20-Poly1305** (AEAD). Serverul transmite doar textul cifrat, fără a avea acces la conținut (Zero-Knowledge).
* **Protecția Parolelor:** Parolele utilizatorilor sunt stocate exclusiv sub formă de hash-uri folosind algoritmul **Argon2** (rezistent la atacuri brute-force și GPU).
* **Managementul Cheilor:** Utilizează **RSA** pentru protejarea cheilor simetrice stocate local (concept demonstrativ).

### 📡 Rețelistică și Backend
* **Server Asincron:** Construit cu bibliotecile `asyncio` și `websockets` pentru performanță ridicată și gestionarea a sute de conexiuni simultane.
* **Mesagerie Offline (Store-and-Forward):** Dacă destinatarul nu este conectat, mesajele criptate sunt stocate persistent în baza de date **SQLite** și livrate automat la reconectare.
* **Rate Limiting:** Protecție avansată împotriva spam-ului și atacurilor DoS (algoritmul *Sliding Window Log*), cu banarea automată a IP-urilor abuzive.
* **Rotirea Log-urilor:** Sistem automat de jurnalizare pentru auditarea activității serverului.

### 💻 Interfață Grafică (GUI)
* **Design Modern:** Interfață „Dark Mode” construită cu **Tkinter**, optimizată pentru claritate.
* **User Experience:** Notificări vizuale pentru statusul conexiunii, bule de chat diferențiate cromatic.
* **Management Contacte:** Funcții de Adăugare/Ștergere contacte și filtrare a istoricului.
* **Export:** Posibilitatea de a salva istoricul conversațiilor („Inbox”) în fișiere text locale.

---

## 🛠️ Tehnologii Utilizate

| Componentă | Tehnologie | Rol |
| :--- | :--- | :--- |
| **Limbaj** | Python 3.11+ | Limbajul principal de dezvoltare |
| **Protocol** | WebSockets | Comunicare full-duplex în timp real |
| **Async** | `asyncio` | Gestionarea I/O neblocant |
| **Cripto** | `cryptography` | Primitivele ChaCha20, RSA |
| **Hashing** | `argon2-cffi` | Securizarea parolelor |
| **DB** | SQLite3 | Stocare persistentă (server-side) |
| **GUI** | Tkinter | Interfața utilizatorului |

---

## ⚙️ Instalare și Rulare

### 1. Clonează Repository-ul
Descarcă codul sursă pe mașina ta locală:
```bash
git clone [https://github.com/OrganizatiaTa/CryptoChat-Core.git](https://github.com/OrganizatiaTa/CryptoChat-Core.git)
cd CryptoChat-Core
