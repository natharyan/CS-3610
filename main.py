import keys
import subprotocols
from OpenSSL import crypto, SSL

import subprotocols.encryptionschemes

if __name__ == '__main__':
    keystore = '../keystore' # public database of keys (private keys are encrypted with a passphrase)
    datadir = '../data'
    subdirA = 'A' # user A
    passphrase = "1234" # take as user input

    # TASK 1: generate 2048-bit RSA keypairs and encrypt/decrypt a message
    keys.generate_keypair(keystore + '/' + subdirA,passphrase)
    message = "ATTACK AT DAWN"
    subprotocols.encryptionschemes.opensslencrypt(message, keystore + '/' + subdirA + '/public_key.pem', datadir + '/' + subdirA)
    decrypted_text = subprotocols.encryptionschemes.openssldecrypt(keystore + '/' + subdirA + '/private_key.pem', datadir + '/' + subdirA + '/encrypted.bin', passphrase) 
    if (message == decrypted_text):
        print("Decryption successful")

    #TASK 2: Establish a secure symmetric key exchange using OpenSSL
    # user B generates a symmetric key and encrypts it using user A's public
    symkey = keys.gensymkey()
    subdirB_A = 'B-A' # user B
    # user B encrypts the symmetric key using user A's public key
    subprotocols.encryptionschemes.opensslencrypt_symkey(symkey, keystore + '/' + subdirA + '/public_key.pem', datadir + '/' + subdirB_A)
    # user A decrypts the symmetric key using their private key
    symkeyAB = subprotocols.encryptionschemes.openssldecrypt_symkey(keystore + '/' + subdirA + '/private_key.pem', datadir + '/' + subdirB_A + '/encrypted.bin', passphrase)
    if (symkey == symkeyAB):
        print("Symmetric key exchange successful")
    
    # user B encrypts a message using the symmetric key and sends it to user A
    message1 = "KNIGHTS SAY NI"
    encryptedAB = subprotocols.encryptionschemes.opensslSymmetric(message1, symkey,encrypt=True)
    # user A decrypts the message using the symmetric key
    decryptedAB = subprotocols.encryptionschemes.opensslSymmetric(encryptedAB, symkeyAB,encrypt=False)
    if (message1 == decryptedAB):
        print("Symmetric encryption/decryption successful")

    
    

