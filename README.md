# Flight Friend — connected prototype

Flight Friend is an India-focused city-to-city sharing prototype. This folder contains the website, private developer dashboard, and backend. The website includes airport search, opt-in traveler profiles, city inspiration, rotating quotes, Terms/Privacy/Safety notices, and anonymous feedback.

## Run it on Windows

1. Extract this ZIP into a normal folder (not inside the ZIP viewer).
2. Double-click `setup.cmd`. It downloads a standalone, checksum-verified Node.js runtime beside the app if Node 22.5+ is not already installed. No Windows Node installer is needed. The first download is about 45 MB; PowerShell may show an increasing byte count while it downloads. Let it finish.
3. Choose a developer username and a password of at least 14 characters, then enter the password again. If the password is too short or the entries differ, setup shows the reason and keeps the window open. Press a key to close it, then run `setup.cmd` again with the corrected details.
4. Double-click `run.cmd` and leave its window open while using the site.
5. Open `http://localhost:3000/`. The developer dashboard is at `http://localhost:3000/admin/` and uses the credentials created during setup.

The local server listens only on this computer. Closing the `run.cmd` window stops it. The setup script creates encryption keys once; never replace or share the resulting `.env` file.

## Real email and phone verification

The local demo login is for development only. Real email verification and SMS one-time codes require a Firebase project and an HTTPS hosted site. The package contains Firebase integration, but it is intentionally not pre-connected to anyone's Firebase project. Before publishing, follow [PUBLISHING.md](PUBLISHING.md), add the Firebase Web app settings to `public/index.html`, enable Email/Password and Phone Authentication, allow the hosted domain, and configure the matching protected server settings. Firebase phone SMS may require a billing-enabled project. Until those project settings are added, real verification is not active.

An HTML file opened directly is a visual preview. It cannot connect to a shared account database or send real verification codes. Use the connected HTTPS site for that.

## Privacy and prototype limits

- Raw Aadhaar numbers, ticket barcodes, payment credentials, and biometrics are not collected.
- Airport suggestions are selected from the supplied Indian airport data; user-entered flight numbers are not checked against an airline or railway system.
- There is no live order or payment flow. Community delivery/order/rating figures are demo data, not a financial credit score.
- Traveler profiles appear publicly only when the user opts into the directory. Optional date and flight number stay private to the developer dashboard.
- Feedback is anonymous and stored for the developer to review. The site thanks the visitor after successful submission.
- Terms, Privacy, and Safety notices are prototype drafts. Add the actual service operator's contact details and get appropriate legal/security review before inviting the public.

## Data and security

The server stores its SQLite database under `data/`. `.env` stores developer access and encryption keys, is excluded from the ZIP, and must remain private. Encrypted account and feedback records cannot be recovered if the keys are lost. Back up the database and keys securely. The local developer dashboard has one admin account and no multi-factor authentication.

