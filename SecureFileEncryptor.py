from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os

# 生成RSA密钥对
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    # 将密钥序列化并保存为文件
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open('private_key.pem', 'wb') as f:
        f.write(pem)

    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open('public_key.pem', 'wb') as f:
        f.write(pem)

# 加密文件
def encrypt_file(file_path, public_key_path):
    # 生成AES密钥
    aes_key = os.urandom(32)
    iv = os.urandom(16)
    
    # 读取公钥
    with open(public_key_path, 'rb') as f:
        public_key = serialization.load_pem_public_key(f.read())

    # 加密AES密钥
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 读取文件内容
    with open(file_path, 'rb') as f:
        data = f.read()

    # 使用AES加密文件内容
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()

    # 保存加密后的文件
    with open(file_path + '.encrypted', 'wb') as f:
        f.write(encrypted_key + iv + encrypted_data)

# 解密文件
def decrypt_file(encrypted_file_path, private_key_path):
    # 读取私钥
    with open(private_key_path, 'rb') as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    # 读取加密文件内容
    with open(encrypted_file_path, 'rb') as f:
        encrypted_key = f.read(256)  # RSA加密的AES密钥长度为256字节
        iv = f.read(16)  # IV长度为16字节
        encrypted_data = f.read()

    # 解密AES密钥
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 使用AES解密文件内容
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # 保存解密后的文件
    with open(encrypted_file_path + '.decrypted', 'wb') as f:
        f.write(decrypted_data)

# 示例使用
if __name__ == '__main__':
    # generate_keys()
    # encrypt_file('file.pdf', 'public_key.pem')
    decrypt_file('file.pdf.encrypted', 'private_key.pem')
