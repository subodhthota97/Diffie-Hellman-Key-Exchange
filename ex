import argparse
import socket
import struct
import os

from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Util.Padding import pad, unpad

def encryption(key, data, nonce):
    cipher = AES.new(key, AES.MODE_GCM, nonce)
    ciphertext, tag = cipher.encrypt_and_digest(pad(data, 16))
    return (nonce + tag + ciphertext)

def decryption(key, data):
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce)
    plaintext = unpad(cipher.decrypt_and_verify(ciphertext, tag), 16)
    return plaintext

def get_key(password):
    salt = os.urandom(16)
    key = PBKDF2(password, salt, 64)
    return (salt, key)

def server(host, port, password):
    salt, key = get_key(password)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(1)

    print(f'Listening on {host}:{port}')

    client_socket, client_address = server_socket.accept()
    print(f'Accepted connection from {client_address[0]}:{client_address[1]}')

    client_salt = client_socket.recv(16)
    if client_salt != salt:
        print('Error: integrity check failed.', file=sys.stderr)
        return

    while True:
        data_len = client_socket.recv(2)
        if not data_len:
            break
        data_len = struct.unpack('!H', data_len)[0]
        data = client_socket.recv(data_len)
        if not data:
            break
        plaintext = decryption(key, data)
        print(plaintext.decode(), end='')
    client_socket.close()

def client(host, port, password, data):
    salt, key = get_key(password)

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))

    client_socket.sendall(salt)

    nonce = os.urandom(16)
    for chunk in [data[i:i + 16384] for i in range(0, len(data), 16384)]:
        ciphertext = encryption(key, chunk, nonce)
        data_len = struct.pack('!H', len(ciphertext))
        client_socket.sendall(data_len + ciphertext)

    client_socket.close
