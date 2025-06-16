from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from os import urandom

def hybrid_encrypt_file(file_path, public_key_path):
    # 1. Generate AES key
    aes_key = urandom(32)  # 256-bit AES key
    iv = urandom(16)

    # 2. Read file content
    with open(file_path, 'rb') as f:
        data = f.read()

    # 3. AES Encrypt the data
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()

    # 4. Load RSA public key
    with open(public_key_path, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    # 5. Save to encrypted file
    with open(file_path + ".secure", 'wb') as f:
        f.write(iv + encrypted_key + encrypted_data)  # Store IV + RSA encrypted AES key + data

    print("File encrypted:", file_path + ".secure")
