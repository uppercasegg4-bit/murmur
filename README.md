# Murmur

Murmur is a peer-to-peer private chat prototype. It uses PeerJS for peer connections and AES-GCM encryption with a shared passphrase.


## Run

Open `index.html` from a secure context (HTTPS; GitHub Pages is recommended). Create a profile name and a shared chat passphrase (minimum 8 characters). Both contacts need the same passphrase for this prototype.


## Features
- Responsive, modern chat UI with light/dark/system theme options
- Accent color and message bubble shape customization
- P2P messaging and file sharing (8 MB maximum)
- Local message storage in IndexedDB
- QR contact card and shareable invite link
- Add friend using invite link or Peer ID
- Contact safety code display
- Optional disappearing messages

## Limitations / security note
This is a prototype, not a Signal-equivalent secure messenger. The shared passphrase design does not provide forward secrecy, audited identity authentication, or an audited Signal Protocol implementation. The contact safety code is not proof of identity. Do not rely on this prototype for high-risk or sensitive communications.

Peer IDs are included in shared invitation links/QR codes; the UI hides them from the primary profile display. Avoid posting invite links publicly.

