from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

def hybrid_decrypt_file(enc_file_path, private_key_path):
    with open(enc_file_path, 'rb') as f:
        content = f.read()

    iv = content[:16]
    encrypted_key = content[16:16+256]  # RSA 2048-bit = 256 bytes
    encrypted_data = content[16+256:]

    with open(private_key_path, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)

    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    output_file = enc_file_path.replace(".secure", ".decrypted")
    with open(output_file, 'wb') as f:
        f.write(decrypted_data)

    print("Decrypted to:", output_file)
