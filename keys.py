from OpenSSL import crypto,SSL
import subprocess
import os

def generate_keypair(filepath,userpassphrase):
    if not os.path.exists(filepath):
        os.makedirs(filepath)
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)
    # Note: I have FILETYPE_PEM, because of this the private key is encrypted using the user's passphrase (so only the user has access to it from the keystore)
    privkey = crypto.dump_privatekey(crypto.FILETYPE_PEM, k, cipher="aes256", passphrase=userpassphrase.encode())
    pkey = crypto.dump_publickey(crypto.FILETYPE_PEM,k)
    # print("Private key: ", privkey)
    # print("Public key: ", pkey)
    with open(filepath + '/private_key.pem', 'wb') as f:
        f.write(privkey)
    with open(filepath + '/public_key.pem', 'wb') as f:
        f.write(pkey)

def gensymkey():
    # k(\kappa) = 2048, the key size will be 256 bytes
    return os.urandom(256)

def load_privkey(filepath, passphrase):
    with open(filepath + '/private_key.pem', 'rb') as f:
        priv_key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read(), passphrase.encode())
    return priv_key

def load_pubkey(filepath):
    with open(filepath + '/public_key.pem', 'rb') as f:
        pub_key = crypto.load_publickey(crypto.FILETYPE_PEM, f.read())
    return pub_key

def gensymmetric():
    # in the question we are given that the security parameter, \kappa = 2048, so the key size will be 256 bytes
    return crypto.rand_bytes(256)


