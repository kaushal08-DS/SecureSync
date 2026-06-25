import os

from cryptography.fernet import Fernet


def generate_key():
    """
    Generate a new encryption key.
    """
    return Fernet.generate_key()


def save_key(key, filename):
    """
    Save encryption key separately.
    """

    key_path = os.path.join("keys", f"{filename}.key")

    with open(key_path, "wb") as file:
        file.write(key)


def encrypt_file(file_path, filename):

    # Generate unique key
    key = generate_key()

    # Save key separately
    save_key(key, filename)

    cipher = Fernet(key)

    # Read original file
    with open(file_path, "rb") as file:
        data = file.read()

    # Encrypt data
    encrypted_data = cipher.encrypt(data)

    # Save encrypted file
    encrypted_path = os.path.join(
        "encrypted_files",
        f"{filename}.gv"
    )

    with open(encrypted_path, "wb") as file:
        file.write(encrypted_data)

    # Remove original plaintext file
    os.remove(file_path)

    key_path = os.path.join(
        "keys",
        f"{filename}.key"
    )

    return encrypted_path, key_path

def decrypt_file(encrypted_path, key_path):

    with open(key_path, "rb") as file:
        key = file.read()

    cipher = Fernet(key)

    with open(encrypted_path, "rb") as file:
        encrypted_data = file.read()

    decrypted_data = cipher.decrypt(encrypted_data)

    return decrypted_data