import base64
import getpass
import hashlib
import json
import os
from pathlib import Path
import secrets
import string

from cryptography.fernet import Fernet, InvalidToken


DATA_FILE = Path("passwords.enc")
SALT_FILE = Path("salt.bin")


def get_or_create_salt():
    """Create a random salt the first time the program runs."""
    if SALT_FILE.exists():
        return SALT_FILE.read_bytes()

    salt = os.urandom(16)
    SALT_FILE.write_bytes(salt)
    return salt


def derive_key(master_password, salt):
    """Create an encryption key from the master password."""
    key = hashlib.pbkdf2_hmac(
        "sha256",
        master_password.encode("utf-8"),
        salt,
        390_000,
        dklen=32
    )

    return base64.urlsafe_b64encode(key)


def load_entries(fernet):
    """Load and decrypt saved password entries."""
    if not DATA_FILE.exists():
        return []

    try:
        encrypted_data = DATA_FILE.read_bytes()
        decrypted_data = fernet.decrypt(encrypted_data)

        return json.loads(decrypted_data.decode("utf-8"))

    except InvalidToken:
        raise ValueError(
            "Wrong master password or damaged password vault."
        )

    except json.JSONDecodeError:
        raise ValueError(
            "Password vault contains invalid data."
        )


def save_entries(fernet, entries):
    """Encrypt password entries and save them to disk."""
    data = json.dumps(entries, indent=2).encode("utf-8")

    encrypted_data = fernet.encrypt(data)

    DATA_FILE.write_bytes(encrypted_data)


def generate_password(length=16):
    """Generate a strong random password."""
    characters = (
        string.ascii_letters
        + string.digits
        + "!@#$%^&*()-_=+"
    )

    while True:
        password = "".join(
            secrets.choice(characters)
            for _ in range(length)
        )

        if (
            any(c.islower() for c in password)
            and any(c.isupper() for c in password)
            and any(c.isdigit() for c in password)
            and any(c in "!@#$%^&*()-_=+" for c in password)
        ):
            return password


def choose_entry(entries):
    """Allow the user to select a saved entry."""
    if not entries:
        print("\nNo password entries found.")
        return None

    print("\nSaved Entries:")

    for index, entry in enumerate(entries, start=1):
        print(
            f"{index}. "
            f"{entry['service']} - "
            f"{entry['username']}"
        )

    try:
        number = int(input("\nEnter entry number: "))
        index = number - 1

        if 0 <= index < len(entries):
            return index

    except ValueError:
        pass

    print("Invalid selection.")
    return None


def add_entry(entries, fernet):
    """Add a new password entry."""
    print("\n--- Add Password ---")

    service = input("Website/Service: ").strip()
    username = input("Username/Email: ").strip()

    password = getpass.getpass(
        "Password (leave blank to generate): "
    )

    if not password:
        password = generate_password()
        print(f"Generated password: {password}")

    entry = {
        "service": service,
        "username": username,
        "password": password
    }

    entries.append(entry)

    save_entries(fernet, entries)

    print("\nPassword saved successfully.")


def retrieve_entry(entries):
    """Retrieve and display a password."""
    print("\n--- Retrieve Password ---")

    index = choose_entry(entries)

    if index is None:
        return

    entry = entries[index]

    print("\nService  :", entry["service"])
    print("Username :", entry["username"])
    print("Password :", entry["password"])


def delete_entry(entries, fernet):
    """Delete a password entry."""
    print("\n--- Delete Password ---")

    index = choose_entry(entries)

    if index is None:
        return

    deleted = entries.pop(index)

    save_entries(fernet, entries)

    print(
        f"\nDeleted entry: {deleted['service']}"
    )


def search_entries(entries):
    """Search saved entries."""
    print("\n--- Search Passwords ---")

    search_term = input(
        "Enter service or username: "
    ).strip().lower()

    found = False

    for entry in entries:
        if (
            search_term in entry["service"].lower()
            or search_term in entry["username"].lower()
        ):
            print(
                f"- {entry['service']} | "
                f"{entry['username']}"
            )
            found = True

    if not found:
        print("No matching entries found.")


def main():
    print("=" * 40)
    print("       LOCAL PASSWORD MANAGER")
    print("=" * 40)

    master_password = getpass.getpass(
        "Enter master password: "
    )

    salt = get_or_create_salt()

    encryption_key = derive_key(
        master_password,
        salt
    )

    fernet = Fernet(encryption_key)

    try:
        entries = load_entries(fernet)

    except ValueError as error:
        print(f"\nError: {error}")
        return

    while True:

        print("\n" + "=" * 40)
        print("1. Add Password")
        print("2. Retrieve Password")
        print("3. Delete Password")
        print("4. Search")
        print("5. Generate Password")
        print("6. Exit")
        print("=" * 40)

        choice = input("Choose an option: ").strip()

        if choice == "1":
            add_entry(entries, fernet)

        elif choice == "2":
            retrieve_entry(entries)

        elif choice == "3":
            delete_entry(entries, fernet)

        elif choice == "4":
            search_entries(entries)

        elif choice == "5":
            try:
                length = int(
                    input("Password length (minimum 12): ")
                )

                if length < 12:
                    print(
                        "Password should be at least 12 characters."
                    )
                else:
                    print(
                        "Generated password:",
                        generate_password(length)
                    )

            except ValueError:
                print("Please enter a valid number.")

        elif choice == "6":
            print("\nGoodbye!")
            break

        else:
            print("\nInvalid option. Please try again.")


if __name__ == "__main__":
    main()