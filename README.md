# 🔐 Password Vault with Claude AI

A small Streamlit app that saves a password for each Gmail / email account, keeps
them encrypted, and has a Claude-powered helper that gives password-safety advice.

## What it does

- **Master password:** one password unlocks your vault. It is never saved anywhere.
- **Encryption:** passwords are encrypted (Fernet + PBKDF2, 480,000 rounds) before they are saved to disk.
- **Per-account passwords:** every Gmail has its own entries, grouped on screen.
- **Strength and reuse check:** warns about weak or reused passwords.
- **Password generator:** makes strong random passwords.
- **Ask Claude:** sends Claude only account names, sites and strength labels. **Real passwords are never sent.**
- **Backup:** download an encrypted backup and restore it later.

## Files

| File | What it is |
|------|-----------|
| `app.py` | The whole app |
| `requirements.txt` | Packages the app needs |
| `README.md` | This guide |

## Run on your own computer

```bash
pip install -r requirements.txt
export ANTHROPIC_API_KEY="your-key-here"   # Windows PowerShell: $env:ANTHROPIC_API_KEY="your-key-here"
streamlit run app.py
```

Get a Claude API key at https://console.anthropic.com. The app works without a key; only the "Ask Claude" tab needs it.

To use a different Claude model, set the `CLAUDE_MODEL` variable (default: `claude-sonnet-5-5`).

## Important safety notes

1. **Free hosting forgets files.** Streamlit Community Cloud erases saved files when the app restarts or sleeps. Use the **Backup** tab to download your vault often.
2. **Never upload `vault_data/` or your API key to GitHub.** The included `.gitignore` already blocks them.
3. **Forgot the master password? It cannot be recovered.** That is what keeps it safe.
4. This is a learning project. For your most important accounts, a trusted password manager (Bitwarden, 1Password) is the safer long-term choice.

---

# Step-by-step guide (explained simply)

## Part 1: Put your code on GitHub (no coding tools needed)

Think of GitHub as a **big online backpack** for your code. Streamlit will open the backpack and run what is inside.

1. **Make an account.** Go to https://github.com and click **Sign up**. Verify your email.
2. **Make a new folder (called a repository).** Click the **+** at the top right, then **New repository**.
3. **Name it**, for example `password-vault`. Choose **Public** (Streamlit's free plan needs it to be public, and that is fine because your passwords are never in the code). Click **Create repository**.
4. **Upload the files.** On the new page click the link **uploading an existing file**.
5. **Drag in the 4 files:** `app.py`, `requirements.txt`, `README.md` and `.gitignore`. If you cannot see `.gitignore` on your computer, skip it; the app still works.
6. Scroll down and click the green **Commit changes** button. Done. Your code is online! 🎉

## Part 2: Get your Claude API key

1. Go to https://console.anthropic.com and sign in.
2. Open **API Keys** and click **Create Key**.
3. **Copy it** and keep it secret, like a house key. Never paste it into GitHub.

## Part 3: Put the app on the internet with Streamlit

1. Go to https://share.streamlit.io and click **Continue with GitHub**. Allow access.
2. Click **Create app** (or **New app**), then choose **Deploy a public app from GitHub**.
3. Fill the boxes:
   - **Repository:** pick `your-name/password-vault`
   - **Branch:** `main`
   - **Main file path:** `app.py`
4. Click **Advanced settings**, find the **Secrets** box and type this (use your real key):
   ```toml
   ANTHROPIC_API_KEY = "paste-your-key-here"
   ```
5. Click **Deploy**. Wait one or two minutes while Streamlit installs things.
6. Your app opens with its own web link. Bookmark it! 🚀

## Part 4: Using the app

1. Open **Create new vault**, choose a name and a strong master password, and click **Create vault**.
2. Go to **Add password**, type a Gmail, a site name and a password (or press 🎲 to generate one), then **Save password**.
3. Open **My passwords** to see them grouped by Gmail. Turn on **Show password** to see and copy one.
4. Open **Ask Claude** and press **Check my vault for problems**.
5. Open **Backup** and download your file. Do this every time you add passwords.

## Fixing common problems

| Problem | Fix |
|---------|-----|
| "No Claude API key found" | Add `ANTHROPIC_API_KEY` in the app's **Settings → Secrets** on Streamlit, then reboot the app |
| App says a package is missing | Check `requirements.txt` is uploaded and spelled exactly right |
| My passwords vanished | The free server restarted. Restore from your backup on the first screen |
| "Wrong master password" | Passwords are case-sensitive. Check Caps Lock |
| Claude could not answer | Check your API key and that your Anthropic account has credits |
