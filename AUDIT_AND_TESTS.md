# Changes and validation report

## Bugs fixed in this edition

1. Removed silent fallback from failed cloud persistence to JSON/in-memory state.
2. Added SQLite state persistence and **atomic CAS version checks**. Conflicting concurrent writes receive HTTP 409 instead of silently overwriting another complaint.
3. Made photo evidence a **private SQLite BLOB**, committed atomically with corresponding complaint or repair event. Invalid photo bytes and failed transactions cannot leave a half-saved complaint.
4. Matched frontend 5 MB/photo limit to the server's Multer limit; consistently enforced maximum 3 photos; added JPEG/PNG/WebP file signature checks and 413 error handling.
5. Evidence delivery requires the user to be logged in and authorized to view the exact complaint. Never exposes a public uploads directory.
6. Removed demo hard-coded login passwords and insecure demo auto-fill from the login screen.
7. Added persistent random session/cron secret generation (`npm run setup`) and protected restart behavior.
8. Prevented Rector reassignment to the same person from first marking that person's active assignment ended.
9. Ensured reopening ends old assignments and resets independent cycle tracking; tightened maintenance visibility to active scope and current assignment.
10. Added stronger account ID/email/profile validation, throttling by login ID or IP, restrictive frame security headers, and live-safe database backups.
11. Removed Netlify/Supabase/Firebase deployment files that misleadingly implied reliable SQLite storage on a serverless host.

## Automated validation

Run `npm test`. The 20 tests cover role/hostel permission checks, password hashing, CSV syntax, state transitions, 48h escalation/closure, 7-day reopening, current assignment access, SQLite durability, image signatures, private binary storage, concurrent write rejection, photo rollback, and database reopen.

Run `npm run backup` to exercise a consistent SQLite database backup.

**Not yet completed:** end-to-end browser tests with installed npm modules, WebP/JPEG/PNG uploads from real phones, web-server load testing with many simultaneous students, external HTTPS deployment, vulnerability scanning, and SMTP delivery. npm package installation could not be performed in the build environment due to network resolution failure. Do not claim universal bug-free status from automated tests alone.

## Suggested manual end-to-end test order

1. Fresh admin bootstrap, login and mandatory password change.
2. Create two hostels; assign different Rectors/Dean/Staff scopes; add rooms and allocate students.
3. Confirm students cannot file complaints for other rooms; other-hostel Rector/Dean/Staff must be denied.
4. Submit a complaint with three real JPEG/PNG/WebP images (under 5 MB each). Log out: image URLs must not display. Log in as the student or assigned Rector: images must open.
5. Assign task, accept, start actual work, add progress photos, complete, confirm as student.
6. Reopen unresolved repair and verify previous assignment ended and fresh 48h clock starts.
7. Simulate late vs timely work start, reminder after 24h and eligible auto-closure after 48h using policy tests.
8. Check emergency/escalated cases never auto-close without Rector verification.
9. Reset user password, test inactive account, CSV import with duplicates, full-room allocation and hostel archive safeguards.
10. Restart Node.js, confirm users/complaints/photo bytes persist; run database backup and restore onto a fresh test instance.
