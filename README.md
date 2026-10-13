# BACE Sunday Register

A website for recording every Sunday programme at BACE. People sign in with a username and password. Coordinators enter reports. Viewers watch the progress live and cannot change anything.

## What it does

- A page for every session: Mridanga, Breakfast, Gauranga Sabha, Nityananda Sabha, Levels L2 to L11, Common Class, Prasadam, Servant Leader Meeting and Raja Vidya.
- Scheduled time against actual start and end, with the delay in minutes. The "Now" buttons fill in the time.
- Speaker, topic, and online and in-person participants for each class.
- Prasadam and breakfast: menu, sponsor, every devotee who served, and how many were fed.
- Test and presentation days add the common class and move prasadam to 1:30 pm.
- A day overview with a message you can copy into WhatsApp, and reports across all Sundays with CSV export.
- Every report shows who updated it last and when.

## Roles

| Role | Can do |
|---|---|
| Viewer | Watch the register live. Cannot change anything. |
| Coordinator | Everything a viewer can, and enter or change reports. |
| Administrator | Everything a coordinator can, and add people, change roles, block access and reset passwords. |

The first administrator is created when the site starts for the first time. Open the **Account** tab to add everyone else and give each person their username and password.

## Put it online (Render)

The site needs a server that stays on and a small disk so your data survives restarts. Free hosting plans erase files when they restart, so use a paid plan with a disk.

1. Create a free account at github.com and make a new private repository. Upload all the files in this folder to it.
2. Create an account at render.com and choose **New**, then **Blueprint**. Connect your GitHub repository.
3. Render reads `render.yaml` and sets up the site with a disk. When it asks for `ADMIN_PASSWORD`, type a strong password of your own (8 or more characters).
4. Wait for the first deploy to finish. Open the address Render gives you, for example `https://bace-sunday-register.onrender.com`.
5. Sign in with username `admin` and the password you chose. Open **Account**, add your coordinators and viewers, and send each person their login.

Any host that runs Node.js 22.13 or newer and keeps a disk will also work (Railway, Fly.io, a small server of your own). Use these settings:

- Start command: `npm start`
- `DATA_DIR`: a folder on the persistent disk
- `ADMIN_USERNAME` and `ADMIN_PASSWORD`: the first administrator, used only on the very first start

If you forget to set `ADMIN_PASSWORD`, the site makes a random one and prints it in the server log once.

## Run it on your own computer

1. Install Node.js 22.13 or newer from nodejs.org.
2. In this folder run: `npm start`
3. Open http://localhost:3000 and sign in with the administrator password shown in the terminal.

There is nothing to install with npm. The site uses only what comes with Node.

## Keeping your data safe

- All data is in one file, `register.db`, inside `DATA_DIR`. Copy that file now and then as a backup.
- The **Reports** tab has **Export all as CSV**. Do this every month and keep the file.
- Passwords are stored as salted scrypt hashes, never as plain text. Sessions last 30 days. After 8 wrong sign-in attempts the account is locked for 15 minutes.
- Always use the https address your host gives you, never plain http, so passwords are encrypted on the way.

## Files

- `server.js`: the server, accounts, roles and database
- `public/index.html`, `public/style.css`, `public/app.js`: the website
- `render.yaml`: one-click setup for Render
