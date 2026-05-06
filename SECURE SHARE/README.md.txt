# SECURE SHARE (AES + RSA)

## Description

This project is a web application that allows users to send and receive files safely.
It uses AES to encrypt files and RSA to protect the encryption key.
The goal of this system is to keep files private and secure during transfer.

---

## Features

* User registration and login
* Secure password using bcrypt
* Authentication using JWT
* Upload and send files
* AES encryption for files
* RSA encryption for key exchange
* Download and decrypt files
* Real-time file transfer using Socket.IO

---

## Installation

Steps to install your project:

```bash
git clone https://github.com/planamayreyl-lab/Secure-File-Sharing-System.git
cd SECURE SHARE
npm install
```

---

## Run the Project

```bash
node server.js
```

Open your browser and go to:

```bash
http://localhost:3000
```

---

## How It Works

1. User uploads a file
2. File is encrypted using AES
3. AES key is encrypted using RSA
4. File is sent to receiver
5. Receiver accepts the file
6. File is decrypted and downloaded

---

## Project Structure

* server.js → backend server
* index.html → frontend
* uploads/ → temporary files
* keys/ → RSA keys
* users.json → user data

---

## Authors

* GROUP 1/  Mayreyl Plana & Nicole sagapay

---

## Notes

* Max file size: 50MB
* Works on local network
* Requires Node.js

---

## Security

* AES-256 file encryption
* RSA-2048 key encryption
* JWT authentication
* bcrypt password hashing
