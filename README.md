# Murmur

Murmur is a responsive peer-to-peer chat prototype.

## Deploy on GitHub Pages
1. Upload `index.html` and `app.js` to the repository root.
2. Open **Settings → Pages**.
3. Select **Deploy from a branch**, branch `main`, folder `/ (root)`.
4. Visit the generated HTTPS site.

## Features in this build
- Responsive desktop two-column layout and mobile full-screen conversation navigation
- Local QR profile / invite link
- Theme (light/dark/system), accent colors and bubble shapes
- Disappearing message timer
- Auto-lock: 30 sec, 1 min, 5 min, 15 min, 30 min, 1 hour, or Never
- Lock now, clear local messages, logout, and two-stage wipe account
- PeerJS peer-to-peer messaging prototype

## Security caveat
This is an experimental prototype, not a Signal replacement or audited secure messenger. Auto-lock is a UI lock, not OS-level protection; browser developer tools/extensions or a compromised device can bypass it. Wipe/delete only removes data from this device, not copies held by contacts. Shared-passphrase encryption lacks forward secrecy and an audited protocol.
