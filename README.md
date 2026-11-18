# Murmur
A static PeerJS chat prototype intended for GitHub Pages.


## Publish with GitHub Pages
1. Create a GitHub repository (for example `murmur`).
2. Upload `index.html` to the repository root.
3. Open **Settings → Pages**.
4. Under Build and deployment, choose **Deploy from a branch**, branch `main`, folder `/ (root)`, then Save.
5. Open the Pages URL after the deployment completes.


## Important security notes
This is an experimental peer-to-peer chat prototype, not a production secure messenger. It uses AES-GCM with a shared passphrase-derived key, but does not implement the Signal Protocol, forward secrecy, ratcheting, audited key management, or authenticated identity. The peer fingerprint is a manual comparison aid only. Use only for testing; do not send highly sensitive information.

Both participants must use the exact same chat passphrase. Peer IDs are stored locally in browser storage; clearing site data may lose your identity and history. File transfer is limited to 8 MB and files are stored locally in IndexedDB.
