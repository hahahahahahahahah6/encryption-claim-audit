from cryptography.fernet import Fernet
def store(data):
    return Fernet(b"placeholder").encrypt(data)
