# Project 02 - Local Password Manager

## Introduction

This project is a local password manager developed as part of my cybersecurity internship. It allows users to securely store and manage their passwords on their local computer.

The passwords are encrypted before being stored on disk, so the actual credentials are not stored as plain text.

## Features

* Master password protection
* Secure password storage
* Symmetric encryption using Fernet
* Key derivation using PBKDF2-HMAC-SHA256
* Random salt generation
* Add password entries
* Retrieve saved passwords
* Delete password entries
* Search saved entries
* Generate strong random passwords
* Encrypted local storage

## Technologies Used

* Python
* Cryptography library
* JSON
* PBKDF2-HMAC-SHA256
* Fernet symmetric encryption

## Project Files

```text
Project-02-Password-Manager/
│
├── password_manager.py
├── README.md
├── requirements.txt
└── .gitignore
```

The actual encrypted password vault and salt file are excluded from GitHub using `.gitignore`.

## How to Run

### 1. Install Python

Make sure Python is installed on your computer.

Check the Python version:

```bash
python --version
```

### 2. Install the required library

Open the terminal inside the project folder and run:

```bash
python -m pip install cryptography
```

### 3. Run the password manager

```bash
python password_manager.py
```

### 4. Enter the master password

The application asks for a master password when it starts.

The master password is used to derive the encryption key for the password vault.

## Main Operations

The application provides the following options:

1. Add Password
2. Retrieve Password
3. Delete Password
4. Search
5. Generate Password
6. Exit

## Security

Passwords are not stored directly as plain text in the password vault.

The application uses:

* A master password
* PBKDF2-HMAC-SHA256 for key derivation
* A randomly generated salt
* Fernet symmetric encryption
* Secure random password generation using Python's `secrets` module

The encrypted password vault and salt file are excluded from GitHub to prevent accidental exposure of stored credentials.

## Learning Outcomes

Through this project, I learned about:

* Password management
* Symmetric encryption
* Secure key derivation
* Random salts
* Encrypted local storage
* Secure password generation
* Basic secure coding practices

## Ethical Use

This project is created for educational and cybersecurity internship purposes. It should only be used to store and manage the user's own credentials on a trusted local computer.
