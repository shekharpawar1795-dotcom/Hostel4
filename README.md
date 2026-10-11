# HostelCare — SQLite Test Edition (Node.js + Express + EJS)

**Updated from the uploaded `hostel3.zip`**. Keeps the existing five-role EJS interface, Node.js/Express backend, complaint state machine, role/hostel scoping and scheduled 48-hour policies. This release uses **one persistent SQLite database** rather than Supabase, Firebase or a memory/JSON fallback. It does **not** pretend that SQLite can persist inside Netlify Functions.

## Quick start — Windows CMD (beginner steps)

**Prerequisite:** Install the current **Node.js 24 LTS** from https://nodejs.org (minimum Node.js 22.13). Do not use Node 20: this release relies on Node's built-in `node:sqlite` module. A warning from Node 22 about experimental SQLite is normal; Node 24 is preferred.

1. **Extract the ZIP**. Open the folder containing `package.json`, `server.js` and `views` in File Explorer. Click the address bar, type `cmd`, press Enter.
2. Run these **four commands** in that CMD window (not Python):

   ```cmd
   npm install
   npm run setup
   npm run admin:init
   npm start
   ```

3. During `npm run admin:init` you'll see **SYSTEM ADMIN LOGIN: HCMSADMIN** and a **random one-time password**. Save it privately; the script prints it only on the first creation. Open **http://localhost:3000**. Log in as `HCMSADMIN` and change your password.
4. In the System Admin dashboard: create a hostel and rooms; add a Rector, Dean, Maintenance Staff and fictional students; assign staff hostels; allocate students to rooms. Each new user has their own generated temporary password, which they must change on first login.
5. Leave the CMD window open. The worker is included in the running server and checks deadlines every five minutes. You **do not need** a second worker window for normal testing.

**Next time** just open CMD in the project folder and run `npm start`. No need to reinstall dependencies or reinitialize accounts. To stop: press `Ctrl+C`.

### One-command automated tests

```cmd
npm test
```

### Where are my records and evidence photos stored?

Everything is stored in `data/hostelcare.sqlite3` (SQLite WAL mode). Student profiles, hostel allocations, complaints, events, and attachments' metadata live in the versioned SQLite application state. **Evidence photo bytes live in a separate private SQLite BLOB table**, and are only returned by `/photos/:id` after login + complaint-scope authorization. Uploaded JPEG/PNG/WebP are verified using file signatures. Limit: **three files, each 5 MB**, per upload. Failed state/image transactions roll back together. There is no public `/uploads` folder or external image API key.

The `data/` folder must be **writable and persistent**. It contains real credentials and private records. Never commit it, your `.env`, or old `.local-hcms-data.json` to GitHub.

### Back up the database

```cmd
npm run backup
```

This creates a consistent `backups/hostelcare-<timestamp>.sqlite3` database backup, **including photo evidence**. Save an encrypted copy outside the server. Test your restore procedure. Do not copy only the live `.sqlite3` file while the site is running (SQLite WAL writes can be pending).

### Optionally import old local JSON test data

If you have the **old** `.local-hcms-data.json` file, run after `npm run setup` and **before** `npm run admin:init`:

```cmd
npm run import:json -- "C:\path\to\old-project\.local-hcms-data.json"
```

This imports accounts, complaints and embedded base64 photos into SQLite. It refuses to overwrite an initialized SQLite database and refuses incomplete remote-only photos. The original JSON may contain insecure demo passwords: reset all imported credentials before sharing. Migration from the old Python/FastAPI SQLite schema or remote Supabase buckets is **not** implemented.

## Roles and functional rules

- **Student:** logs in with assigned URN, changes their one-time password, files complaints for their active room, views only their complaints, confirms a repair or reopens eligible complaints; optionally supplies photos/feedback.
- **Rector:** manages complaints in assigned hostels, classifies/rejects/assigns/reassigns, and verifies exceptional cases; cannot act outside assigned hostel scope.
- **Maintenance Staff:** works only current assigned cases with active hostel scope; accepts, starts, records progress/holds, resumes and completes with evidence.
- **Dean:** views only escalated complaints in assigned hostels, adds directives.
- **System Admin:** adds/archives hostels; manages rooms, users, scopes, allocations, password resets and bulk student import. Cannot delete a hostel with records.
- **Deadline A:** a distinct **48-hour period for every work cycle** to have actually started, otherwise records a Dean escalation. Late start does not erase the breach.
- **Deadline B:** after repair completion, reminder at 24 hours and **eligible auto-closure at 48 hours** absent student confirmation. Emergency and escalated cases need Rector verification. Reopening makes a fresh work cycle; eligible auto-closed cases can be reopened for seven days.

## Hosting — important Netlify/SQLite incompatibility

**This complete Node/Express/EJS + SQLite project must run on a server with persistent disk**, such as a small always-on VM or a college-hosted machine. On Netlify Functions, local SQLite files and uploaded photos on disk do **not** persist reliably across requests/redeployments. Its scheduled worker is also not a normal always-on process. For that reason, Netlify function configurations from the old ZIP were intentionally removed. The Node/EJS stack is preserved, but a **Netlify-only free-tier deployment is not supported by this SQLite edition**.

A cloud VM with Node 24 and a persistent data directory can serve this code when properly secured behind HTTPS. Set up reverse proxy, backups, firewall and monitoring before any external pilot; never expose credentials via HTTP.

## Security and quality status

The included policy, SQLite transaction/concurrency, photo-signature and evidence-persistence tests run with `npm test`. **This project has not been verified in a full browser test or publicly deployed in this environment**, because downloading Express/EJS/Multer npm packages is blocked here. Even passing tests cannot prove every form and edge case works. Test all workflows on Windows before hosting; do not use personal student data without institutional approval.

Known limitations: SQLite app state is still stored as a single versioned JSON snapshot (although photos are separate native BLOBs), and concurrent writes can yield a safe 409 retry message. Not yet a fully normalized SQL schema. No SMTP email delivery, MFA, malware scanning, tested multi-user load/uptime, or audited off-site backups. Automatic deadlines work only while the server/worker is running. Use fictional identities for the pilot.
