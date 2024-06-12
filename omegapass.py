import os
import base64
import getpass
from cryptography.fernet import Fernet
from accessible_output2 import outputs

def generate_key():
    key = Fernet.generate_key()
    key_path = os.path.join(os.getenv("APPDATA"), "OmegaPass", "omega_key.key")
    with open(key_path, "wb") as key_file:
        key_file.write(key)

def load_key():
    key_path = os.path.join(os.getenv("APPDATA"), "OmegaPass", "omega_key.key")
    return open(key_path, "rb").read()

if not os.path.exists(os.path.join(os.getenv("APPDATA"), "OmegaPass")):
    os.makedirs(os.path.join(os.getenv("APPDATA"), "OmegaPass"))

if not os.path.exists(os.path.join(os.getenv("APPDATA"), "OmegaPass", "omega_key.key")):
    generate_key()

key = load_key()
cipher_suite = Fernet(key)

def encrypt_data(data):
    encoded_data = data.encode()
    encrypted_data = cipher_suite.encrypt(encoded_data)
    return encrypted_data

def decrypt_data(encrypted_data):
    decrypted_data = cipher_suite.decrypt(encrypted_data)
    return decrypted_data.decode()

PASSWORD_FILE = os.path.join(os.getenv("APPDATA"), "OmegaPass", "passwords.txt")

def add_password(service, username, password):
    encrypted_service = encrypt_data(service)
    encrypted_username = encrypt_data(username)
    encrypted_password = encrypt_data(password)
    with open(PASSWORD_FILE, "a") as f:
        f.write(f"{encrypted_service.decode()},{encrypted_username.decode()},{encrypted_password.decode()}\n")

def view_passwords():
    speaker = outputs.auto.Auto()
    if os.path.exists(PASSWORD_FILE):
        passwords = []
        with open(PASSWORD_FILE, "r") as f:
            for line in f.readlines():
                encrypted_service, encrypted_username, encrypted_password = line.strip().split(",")
                service = decrypt_data(encrypted_service.encode())
                username = decrypt_data(encrypted_username.encode())
                password = decrypt_data(encrypted_password.encode())
                passwords.append((service, username, password))
        if passwords:
            speaker.output("Stored Passwords:")
            for idx, password in enumerate(passwords, 1):
                service, username, password = password
                speaker.output(f"{idx}. Service: {service}, Username: {username}, Password: {password}")
        else:
            speaker.output("No passwords saved yet.")
    else:
        speaker.output("No passwords saved yet.")

def delete_password(service):
    speaker = outputs.auto.Auto()
    if os.path.exists(PASSWORD_FILE):
        lines = []
        with open(PASSWORD_FILE, "r") as f:
            lines = f.readlines()
        with open(PASSWORD_FILE, "w") as f:
            for line in lines:
                encrypted_service, _, _ = line.strip().split(",")
                decrypted_service = decrypt_data(encrypted_service.encode())
                if decrypted_service != service:
                    f.write(line)
        speaker.output(f"Password for {service} deleted.")
    else:
        speaker.output("No passwords saved yet.")

def display_help():
    speaker = outputs.auto.Auto()
    speaker.output("Omega Pass - Password Manager")
    speaker.output("Commands:")
    speaker.output("1. add - Add a new password")
    speaker.output("2. view - View stored passwords")
    speaker.output("3. delete - Delete a password")
    speaker.output("4. help - Show this help message")
    speaker.output("5. exit - Exit Omega Pass")

def menu():
    speaker = outputs.auto.Auto()
    while True:
        speaker.output("\nOmega Pass - Password Manager")
        speaker.output("Enter 'help' for commands.")
        choice = input("Enter your choice: ")

        if choice == "add":
            service = input("Enter the service name: ")
            username = input("Enter the username: ")
            password = getpass.getpass("Enter the password: ")
            add_password(service, username, password)
        elif choice == "view":
            view_passwords()
        elif choice == "delete":
            service = input("Enter the service name to delete: ")
            delete_password(service)
        elif choice == "help":
            display_help()
        elif choice == "exit":
            break
        else:
            speaker.output("Invalid choice, please try again.")

if __name__ == "__main__":
    menu()
