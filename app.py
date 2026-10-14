"""
Password Vault with a Claude AI helper (Streamlit).

- Passwords are encrypted with a key made from your MASTER PASSWORD.
- Each Gmail / email account can have its own password (grouped on screen).
- Claude never sees your real passwords. It only sees labels like
  "gmail account, site name, strength: weak, reused: yes".
"""

import base64
import hashlib
import json
import os
import re
import secrets
import string
import uuid
from datetime import datetime, timezone
from pathlib import Path

import streamlit as st
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ----------------------------------------------------------------------------
# Settings
# ----------------------------------------------------------------------------
DATA_DIR = Path(os.environ.get("VAULT_DATA_DIR", "vault_data"))
CLAUDE_MODEL = os.environ.get("CLAUDE_MODEL", "claude-sonnet-5-5")
KDF_ITERATIONS = 480_000
MIN_MASTER_LENGTH = 8
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "123456789", "qwerty", "abc123",
    "password1", "111111", "iloveyou", "admin", "welcome", "letmein",
}


# ----------------------------------------------------------------------------
# Encryption helpers
# ----------------------------------------------------------------------------
def vault_path(vault_name: str) -> Path:
    """Turn a vault name into a safe file name."""
    digest = hashlib.sha256(vault_name.strip().lower().encode()).hexdigest()[:32]
    return DATA_DIR / f"{digest}.json"


def derive_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=KDF_ITERATIONS
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))


def encrypt_entries(entries: list, key: bytes) -> str:
    return Fernet(key).encrypt(json.dumps(entries).encode()).decode()


def decrypt_entries(token: str, key: bytes) -> list:
    return json.loads(Fernet(key).decrypt(token.encode()).decode())


def build_vault_file(entries: list, key: bytes, salt: bytes) -> dict:
    return {
        "version": 1,
        "salt": base64.b64encode(salt).decode(),
        "data": encrypt_entries(entries, key),
    }


def write_vault_file(path: Path, content: dict) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(content))
    tmp.replace(path)  # atomic: never leaves a half-written file


def create_vault(vault_name: str, master_password: str):
    path = vault_path(vault_name)
    if path.exists():
        raise FileExistsError("A vault with this name already exists.")
    salt = secrets.token_bytes(16)
    key = derive_key(master_password, salt)
    write_vault_file(path, build_vault_file([], key, salt))
    return key, []


def unlock_vault(vault_name: str, master_password: str):
    path = vault_path(vault_name)
    if not path.exists():
        raise FileNotFoundError("No vault with this name.")
    content = json.loads(path.read_text())
    salt = base64.b64decode(content["salt"])
    key = derive_key(master_password, salt)
    try:
        entries = decrypt_entries(content["data"], key)
    except InvalidToken:
        raise ValueError("Wrong master password.")
    return key, entries


def save_entries(vault_name: str, key: bytes, entries: list) -> None:
    path = vault_path(vault_name)
    content = json.loads(path.read_text())
    salt = base64.b64decode(content["salt"])
    write_vault_file(path, build_vault_file(entries, key, salt))


def import_backup(vault_name: str, master_password: str, raw: bytes):
    """Restore a vault from a downloaded backup file."""
    content = json.loads(raw.decode())
    salt = base64.b64decode(content["salt"])
    key = derive_key(master_password, salt)
    try:
        entries = decrypt_entries(content["data"], key)
    except InvalidToken:
        raise ValueError("Wrong master password for this backup.")
    write_vault_file(vault_path(vault_name), content)
    return key, entries


# ----------------------------------------------------------------------------
# Password helpers
# ----------------------------------------------------------------------------
def generate_password(length: int = 16, symbols: bool = True) -> str:
    alphabet = string.ascii_letters + string.digits + ("!@#$%^&*()-_=+" if symbols else "")
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(c.islower() for c in pw)
            and any(c.isupper() for c in pw)
            and any(c.isdigit() for c in pw)
            and (not symbols or any(c in "!@#$%^&*()-_=+" for c in pw))
        ):
            return pw


def password_strength(pw: str) -> str:
    if pw.lower() in COMMON_PASSWORDS or len(pw) < 8:
        return "weak"
    kinds = sum([
        any(c.islower() for c in pw),
        any(c.isupper() for c in pw),
        any(c.isdigit() for c in pw),
        any(not c.isalnum() for c in pw),
    ])
    if len(pw) >= 14 and kinds >= 3:
        return "strong"
    if len(pw) >= 10 and kinds >= 3:
        return "medium"
    return "weak"


def find_reused(entries: list) -> set:
    """Return ids of entries whose password is used more than once."""
    counts = {}
    for e in entries:
        counts[e["password"]] = counts.get(e["password"], 0) + 1
    return {e["id"] for e in entries if counts[e["password"]] > 1}


def safe_vault_summary(entries: list) -> str:
    """Text for Claude. Contains NO real passwords."""
    if not entries:
        return "The vault is empty."
    reused = find_reused(entries)
    lines = []
    for e in entries:
        lines.append(
            f"- account: {e['email']} | site: {e['site']} | "
            f"strength: {password_strength(e['password'])} | "
            f"reused: {'yes' if e['id'] in reused else 'no'} | "
            f"length: {len(e['password'])} | added: {e['created'][:10]}"
        )
    return "\n".join(lines)


# ----------------------------------------------------------------------------
# Claude helper
# ----------------------------------------------------------------------------
def get_api_key():
    key = os.environ.get("ANTHROPIC_API_KEY")
    if key:
        return key
    try:
        return st.secrets.get("ANTHROPIC_API_KEY")
    except Exception:
        return None


def ask_claude(question: str, entries: list, history: list) -> str:
    api_key = get_api_key()
    if not api_key:
        return ("No Claude API key found. Add ANTHROPIC_API_KEY to your "
                "Streamlit secrets (see README), then try again.")
    import anthropic

    system = (
        "You are a friendly password-safety coach inside a password manager app. "
        "You are given a summary of the user's saved accounts. It never includes real "
        "passwords, and you must never ask the user to type or paste a real password. "
        "Give short, clear, practical advice. Mention weak or reused passwords by "
        "account and site. Recommend unique passwords per account and two-step "
        "verification for Gmail.\n\nVault summary:\n" + safe_vault_summary(entries)
    )
    messages = [{"role": m["role"], "content": m["content"]} for m in history]
    messages.append({"role": "user", "content": question})
    try:
        client = anthropic.Anthropic(api_key=api_key)
        resp = client.messages.create(
            model=CLAUDE_MODEL, max_tokens=800, system=system, messages=messages
        )
        return "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")
    except Exception as exc:  # show a friendly message instead of crashing
        return f"Claude could not answer right now ({type(exc).__name__}). Please try again."


# ----------------------------------------------------------------------------
# Screens
# ----------------------------------------------------------------------------
def login_screen():
    st.title("🔐 My Password Vault")
    st.write("Create a vault, or unlock the one you already made.")
    st.caption("Your master password is never saved. If you forget it, nobody can recover your vault.")

    tab_open, tab_new = st.tabs(["Unlock vault", "Create new vault"])

    with tab_open:
        name = st.text_input("Vault name", key="open_name")
        master = st.text_input("Master password", type="password", key="open_master")
        if st.button("Unlock", type="primary"):
            try:
                key, entries = unlock_vault(name, master)
                st.session_state.update(vault=name, key=key, entries=entries, chat=[])
                st.rerun()
            except (FileNotFoundError, ValueError) as exc:
                st.error(str(exc))

    with tab_new:
        name = st.text_input("Choose a vault name", key="new_name")
        master = st.text_input("Choose a master password", type="password", key="new_master")
        again = st.text_input("Type the master password again", type="password", key="new_again")
        if st.button("Create vault"):
            if not name.strip():
                st.error("Please type a vault name.")
            elif len(master) < MIN_MASTER_LENGTH:
                st.error(f"Master password must be at least {MIN_MASTER_LENGTH} characters.")
            elif master != again:
                st.error("The two master passwords do not match.")
            else:
                try:
                    key, entries = create_vault(name, master)
                    st.session_state.update(vault=name, key=key, entries=entries, chat=[])
                    st.rerun()
                except FileExistsError as exc:
                    st.error(str(exc))

    with st.expander("Have a backup file? Restore it"):
        r_name = st.text_input("Vault name to restore as", key="r_name")
        r_master = st.text_input("Master password of the backup", type="password", key="r_master")
        r_file = st.file_uploader("Backup file (.json)", type="json", key="r_file")
        if st.button("Restore backup"):
            if not (r_name.strip() and r_file):
                st.error("Please give a vault name and choose a backup file.")
            else:
                try:
                    key, entries = import_backup(r_name, r_master, r_file.getvalue())
                    st.session_state.update(vault=r_name, key=key, entries=entries, chat=[])
                    st.rerun()
                except (ValueError, KeyError, json.JSONDecodeError):
                    st.error("Could not restore. Check the file and master password.")


def add_tab():
    st.subheader("Add a password")
    st.caption("Use one different password for each Gmail / email account.")

    st.session_state.setdefault("new_pw", "")
    col1, col2, col3 = st.columns([2, 1, 1])
    length = col2.slider("Length", 10, 32, 16)
    symbols = col3.checkbox("Symbols", value=True)
    if col1.button("🎲 Generate strong password"):
        st.session_state["new_pw"] = generate_password(length, symbols)

    with st.form("add_form", clear_on_submit=True):
        email = st.text_input("Gmail / email address")
        site = st.text_input("Site or app name (example: Facebook)", value="Gmail")
        password = st.text_input("Password", type="password", value=st.session_state["new_pw"])
        note = st.text_input("Note (optional)")
        submitted = st.form_submit_button("Save password", type="primary")

    if submitted:
        email, site = email.strip(), site.strip()
        if not EMAIL_RE.match(email):
            st.error("Please type a valid email address.")
        elif not site:
            st.error("Please type a site or app name.")
        elif not password:
            st.error("Please type or generate a password.")
        elif any(e["email"].lower() == email.lower() and e["site"].lower() == site.lower()
                 for e in st.session_state.entries):
            st.error("You already saved this email for this site. Delete the old one first.")
        else:
            st.session_state.entries.append({
                "id": uuid.uuid4().hex,
                "email": email,
                "site": site,
                "password": password,
                "note": note.strip(),
                "created": datetime.now(timezone.utc).isoformat(),
            })
            save_entries(st.session_state.vault, st.session_state.key, st.session_state.entries)
            st.session_state["new_pw"] = ""
            st.success(f"Saved password for {email} on {site}.")


def list_tab():
    st.subheader("My saved passwords")
    entries = st.session_state.entries
    if not entries:
        st.info("Nothing saved yet. Use the 'Add password' tab.")
        return

    search = st.text_input("🔎 Search by email or site").strip().lower()
    reused = find_reused(entries)
    emails = sorted({e["email"].lower() for e in entries})
    shown_any = False

    for em in emails:
        group = [e for e in entries if e["email"].lower() == em
                 and (search in e["email"].lower() or search in e["site"].lower())]
        if not group:
            continue
        shown_any = True
        st.markdown(f"#### 📧 {em}")
        for e in group:
            label = password_strength(e["password"])
            icon = {"strong": "🟢", "medium": "🟡", "weak": "🔴"}[label]
            warn = " ⚠️ reused" if e["id"] in reused else ""
            with st.expander(f"{icon} {e['site']} ({label}){warn}"):
                if st.toggle("Show password", key=f"show_{e['id']}"):
                    st.code(e["password"], language=None)
                else:
                    st.text("••••••••••••")
                if e["note"]:
                    st.caption(f"Note: {e['note']}")
                st.caption(f"Saved on {e['created'][:10]}")
                if st.button("🗑️ Delete", key=f"del_{e['id']}"):
                    st.session_state.entries = [x for x in entries if x["id"] != e["id"]]
                    save_entries(st.session_state.vault, st.session_state.key,
                                 st.session_state.entries)
                    st.rerun()
    if not shown_any:
        st.warning("No match found.")


def ai_tab():
    st.subheader("🤖 Ask Claude")
    st.caption("Claude sees only account names, sites and strength labels. It never sees your real passwords.")

    quick = st.columns(2)
    if quick[0].button("Check my vault for problems"):
        st.session_state["pending_q"] = "Review my vault. Which accounts need a better password and why?"
    if quick[1].button("How do I make Gmail safer?"):
        st.session_state["pending_q"] = "Give me simple steps to protect my Gmail accounts."

    for m in st.session_state.chat:
        with st.chat_message(m["role"]):
            st.write(m["content"])

    question = st.chat_input("Ask about password safety...") or st.session_state.pop("pending_q", None)
    if question:
        with st.chat_message("user"):
            st.write(question)
        with st.chat_message("assistant"):
            with st.spinner("Claude is thinking..."):
                answer = ask_claude(question, st.session_state.entries, st.session_state.chat)
            st.write(answer)
        st.session_state.chat += [
            {"role": "user", "content": question},
            {"role": "assistant", "content": answer},
        ]


def backup_tab():
    st.subheader("💾 Backup")
    st.write(
        "Free hosting can erase saved files when the app restarts. "
        "Download a backup often. The file is encrypted, so it is safe to keep."
    )
    path = vault_path(st.session_state.vault)
    if path.exists():
        st.download_button(
            "Download encrypted backup",
            data=path.read_bytes(),
            file_name="vault_backup.json",
            mime="application/json",
        )


def main():
    st.set_page_config(page_title="Password Vault", page_icon="🔐")
    if "key" not in st.session_state:
        login_screen()
        return

    with st.sidebar:
        st.write(f"Vault: **{st.session_state.vault}**")
        st.write(f"Saved passwords: **{len(st.session_state.entries)}**")
        if st.button("🔒 Lock vault"):
            for k in list(st.session_state.keys()):
                del st.session_state[k]
            st.rerun()

    t1, t2, t3, t4 = st.tabs(["My passwords", "Add password", "Ask Claude", "Backup"])
    with t1:
        list_tab()
    with t2:
        add_tab()
    with t3:
        ai_tab()
    with t4:
        backup_tab()


main()
