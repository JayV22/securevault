import streamlit as st
from hybrid_encrypt import hybrid_encrypt_file
from hybrid_decrypt import hybrid_decrypt_file
from keygen import generate_rsa_keypair
import subprocess
import os
import base64
import hashlib
import json
import rsa
import streamlit.components.v1 as components
import logging
import sys
import time
import socket

st.title("🔐 SecureVault – File Encryption & Decryption")
st.markdown("Hybrid Encryption using AES + RSA")

menu = st.sidebar.radio("Choose Operation", ["Generate RSA Keys", "Encrypt File", "Decrypt File"])

if menu == "Generate RSA Keys":
    if st.button("Generate RSA Key Pair"):
        generate_rsa_keypair()
        st.success("Keys generated: `private_key.pem`, `public_key.pem`")

elif menu == "Encrypt File":
    uploaded_file = st.file_uploader("Upload File to Encrypt")
    public_key_file = st.file_uploader("Upload Receiver's Public Key", type=["pem"])
    
    if uploaded_file and public_key_file:
        with open(uploaded_file.name, "wb") as f:
            f.write(uploaded_file.read())

        with open("public_key.pem", "wb") as f:
            f.write(public_key_file.read())

        if st.button("Encrypt"):
            hybrid_encrypt_file(uploaded_file.name, "public_key.pem")
            st.success(f"File encrypted: {uploaded_file.name}.secure")

elif menu == "Decrypt File":
    enc_file = st.file_uploader("Upload Encrypted File (.secure)")
    private_key_file = st.file_uploader("Upload Your Private Key", type=["pem"])

    if enc_file and private_key_file:
        # Write the encrypted file to disk
        with open(enc_file.name, "wb") as f:
            f.write(enc_file.read())

        # Write the private key to disk
        with open("private_key.pem", "wb") as f:
            f.write(private_key_file.read())

        # Debug: Check if private key is loaded correctly
        try:
            with open("private_key.pem", "rb") as key_file:
                private_key_data = key_file.read()
                private_key = rsa.PrivateKey.load_pkcs1(private_key_data)
            st.info("Private key loaded successfully")
        except rsa.pkcs1.DecryptionError as decryption_error:
            st.error(f"Private key decryption failed: {decryption_error}")
            
        except Exception as e:
            st.error(f"Failed to load private key: {e}")
            # Skip further execution if private key loading fails
            
        
        # Continue processing if no error occurred:
        if st.button("Decrypt"):
            try:
                # Debugging: Check private key and file being decrypted
                st.write(f"Attempting to decrypt file: {enc_file.name}")
                st.write("Private key type:", type(private_key))
                
                # Perform decryption
                hybrid_decrypt_file(enc_file.name, "private_key.pem")
                st.success(f"Decrypted: {enc_file.name.replace('.secure', '.decrypted')}")
            except ValueError as e:
                st.error(f"Decryption failed: {e}")
            except Exception as e:
                st.error(f"Unexpected error during decryption: {e}")


# New menu option
elif menu == "Send/Receive Files":
    transfer_mode = st.radio("Mode", ["Send Encrypted File", "Receive Encrypted File"])

    if transfer_mode == "Send Encrypted File":
        enc_file = st.file_uploader("Upload Encrypted File to Send", type=["secure"])
        host = st.text_input("Receiver IP Address", "127.0.0.1")
        port = st.number_input("Port", value=9999, step=1)

        if enc_file:
            with open(enc_file.name, "wb") as f:
                f.write(enc_file.read())

            if st.button("Send File"):
                result = subprocess.run(["python", "sender.py", enc_file.name, host, str(port)])
                if result.returncode == 0:
                    st.success(f"File sent to {host}:{port}")
                else:
                    st.error("File sending failed.")

    elif transfer_mode == "Receive Encrypted File":
        output_name = st.text_input("Save as (e.g. received.secure)", value="received.secure")
        port = st.number_input("Listening Port", value=9999, step=1)

        if st.button("Start Receiver"):
            st.warning("Receiver started. Waiting for file...")
            # Use Popen to keep listening in background
            subprocess.Popen(["python", "receiver.py", output_name, str(port)])
            st.success(f"Listening on port {port}, file will be saved as `{output_name}`")
