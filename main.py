import keys
import subprotocols
from OpenSSL import crypto, SSL

import subprotocols.encryptionschemes

if __name__ == '__main__':
    print("called")
    keystore = '../keystore' # public database of keys (private keys are encrypted with a passphrase)
    datadir = '../data'
    subdir = 'A' # user A
    passphrase = "1234" # take as user input

    # TASK 1: generate 2048-bit RSA keypairs and encrypt/decrypt a message
    keys.generate_keypair(keystore + '/' + subdir,passphrase)
    message = "ATTACK AT DAWN"
    subprotocols.encryptionschemes.opensslencrypt(message, keystore + '/' + subdir + '/public_key.pem', datadir + '/' + subdir)
    decrypted_text = subprotocols.encryptionschemes.openssldecrypt(keystore + '/' + subdir + '/private_key.pem', datadir + '/' + subdir + '/encrypted.bin', passphrase, datadir + '/' + subdir) 
    if (message == decrypted_text):
        print("Decryption successful")

    # TASK 2: Establish a secure symmetric key exchange using OpenSSL
    # user B generates a symmetric key and encrypts it using user A's public
    # symkey = keys.gensymkey()
    # subdirB_A = 'B-A' # user B
    # subprotocols.encryptionschemes.opensslencrypt_symmetric(symkey, keystore + '/' + subdir + '/public_key.pem', datadir + '/' + subdirB_A)
    # # user A decrypts the symmetric key
    # symkeyB_A = subprotocols.encryptionschemes.openssldecrypt(keystore + '/' + subdir + '/private_key.pem', datadir + '/' + subdirB_A + '/encrypted.bin', passphrase, datadir + '/' + subdirB_A)
    # if (symkey == symkeyB_A):
    #     print("Symmetric key exchange successful")