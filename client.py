import os
import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


def gen_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_key = private_key.public_key()

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    os.mkdir("keys")

    with open('keys/private_key.pem', 'wb') as f:
        f.write(pem)

    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open('keys/public_key.pem', 'wb') as f:
        f.write(pem)

    print("==========Keys Generated==========")

#Checks is Keys exist
def keys_exist():
    if os.path.exists('keys/private_key.pem') and os.path.exists('keys/public_key.pem'):
        return True
    else:
        return False

def obtain_public_key(sock):
    try:
        data = sock.recv(4096)
        print("Data Received!")
        return str(data, encoding='utf-8')
    except Exception as e:
        print("No Data")
        return

#Stores Server's Public Key
def store_server_pk(pk):
    if not os.path.exists("server-keys/public_key.pem"):
        os.mkdir("server-keys")
    with open("server-keys/public_key.pem", "wb") as f:
        f.write(pk.encode())
        f.close()
    print("Server Public Key Copied")

#Reads OUR Public Key
def read_public_key():
    with open("keys/public_key.pem", "rb") as key_file:
        public_key = key_file.read()
    return public_key

#Sends OUR Public Key
def send_public_key(sock, pk):
    print("Sending Public Key...")
    sock.send(pk)
    print("Public Key Sent")

#Receives Encrypted Message from server
def receive_encrypted_message(sock):
    data = sock.recv(4096)
    print("Encrypted Message Received!")
    return data

#Decrypt Data with OUR Private Key
def decrypt_data(data):
    with open("keys/private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    decrypted_message = private_key.decrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return str(decrypted_message, encoding='utf-8')

#Writes the Decrypted file
def write_decrypted_file(file_name, decrypted_message):
    print("Writing to File...")
    if not os.path.exists(file_name):
        with open(file_name, "w") as f:
            f.write(decrypted_message)
            f.close()
        print("Done Writing to File!")
    else:
        print("File Already Exists!")
        return

#Reads the newly created file from server
def read_new_file(file_name):
    if os.path.exists(file_name):
        with open(file_name, "r") as f:
            print(f.read())
    else:
        print("File Does Not Exist!")
        return

def main():

    if not keys_exist():
        gen_keys()
    else:
        print("Keys Exist\nAttempting to Connect...")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    IP = "127.0.0.1"
    PORT = 10001

    try:
        sock.connect((IP, PORT))
    except Exception as e:
        print(e)
        sock.close()
        exit()

    while(1):
        print(str(sock.getpeername()))
        print("Connected")

        while(1):
            try:
                server_pk = obtain_public_key(sock)
                store_server_pk(server_pk)
                send_public_key(sock, read_public_key())
                server_message = decrypt_data(receive_encrypted_message(sock))
                file_name = str(input("Enter a File Name: "))
                write_decrypted_file(file_name, server_message)
                read_new_file(file_name)
                break
            except Exception as e:
                print(e)
                sock.close()
                exit()

        break

    sock.close()
    exit()

if __name__ == '__main__':
    main()
