# SecureShare

A real-time encrypted file transfer app. Send files directly to online users — encrypted with AES-256 + RSA-2048 before leaving your device.

## Setup

```bash
npm install express socket.io multer jsonwebtoken bcrypt
node server.js
```

Then open `http://localhost:3000` in your browser.

## How it works

1. Register an account — an RSA key pair is generated for you automatically.
2. Log in and see who's online.
3. Select a recipient, pick a file (max 50 MB), and send.
4. The recipient gets a real-time prompt to accept or decline.
5. On accept, the file is decrypted and downloaded.

## Encryption

Files are encrypted with a random AES-256 key. That key is then encrypted with the recipient's RSA-2048 public key, so only they can decrypt it.

## Notes

- User accounts are saved in `users.json` and survive server restarts.
- Change `JWT_SECRET` in `server.js` before deploying.
- Private keys are stored in plaintext — not recommended for public production use.
