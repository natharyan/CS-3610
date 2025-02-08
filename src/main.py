import keys
import subroutines
from OpenSSL import crypto, SSL
import socket
import threading
import time
import os

import subroutines.certificate # user defined module
import subroutines.encryptionschemes # user defined module

def send_message(message, host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        if isinstance(message, str):
            s.sendall(message.encode())
        else:
            s.sendall(message)
        print(f"Sent message to {host}:{port}")
        s.close()

def receive_message(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow reuse of the address
        s.bind((host, port))
        s.listen()
        print(f"Listening on {host}:{port}")
        conn, addr = s.accept()
        with conn:
            data = conn.recv(1024)
            print(f"Received message from {addr}")
            return data

def receive_message_thread(host, port, result):
    result.append(receive_message(host, port))

if __name__ == '__main__':
    # port assignments, user A, user B, and CA. Communication: A <-> CA, B <-> A, B <-> CA
    PORT_A = 65432
    PORT_B = 65433
    PORT_CA = 65434

    print("Port assignments:")
    print(f"User A: localhost:{PORT_A}")
    print(f"User B: localhost:{PORT_B}")
    print(f"CA: localhost:{PORT_CA}")

    keystore = '../keystore' # public database of keys (private keys are encrypted with a passphrase)
    datadir = '../data'
    subdirA = 'A' # user A
    passphrase = "1234" # take as user input when retrieving the private key

# ---------------------------- #

    # TASK 1: generate 2048-bit RSA keypairs and encrypt/decrypt a message
    keys.generate_keypair(keystore + '/' + subdirA, passphrase)
    message = "ATTACK AT DAWN"
    subroutines.encryptionschemes.opensslencrypt(message, keystore + '/' + subdirA + '/public_key.pem', datadir + '/' + subdirA)
    decrypted_text = subroutines.encryptionschemes.openssldecrypt(keystore + '/' + subdirA + '/private_key.pem', datadir + '/' + subdirA + '/encrypted.bin', passphrase) 
    if (message == decrypted_text):
        print("Decryption successful")

# ---------------------------- #

    # TASK 2: Establish a secure symmetric key exchange using OpenSSL
    # user B generates a symmetric key and encrypts it using user A's public
    symkey = keys.gensymkey()
    subdirB_A = 'B-A' # user B
    # user B encrypts the symmetric key using user A's public key
    subroutines.encryptionschemes.opensslencrypt_symkey(symkey, keystore + '/' + subdirA + '/public_key.pem', datadir + '/' + subdirB_A)
    # start a thread to receive the encrypted symmetric key
    encrypted_symkey_result = []
    receive_thread = threading.Thread(target=receive_message_thread, args=('localhost', PORT_A, encrypted_symkey_result))
    receive_thread.start()
    time.sleep(1)
    # send the encrypted symmetric key to user A
    send_message(datadir + '/' + subdirB_A + '/encrypted.bin', 'localhost', PORT_A)
    # wait for the thread to finish and get the result
    receive_thread.join()
    encrypted_symkey_path = encrypted_symkey_result[0]
    # user A decrypts the symmetric key using their private key
    symkeyAB = subroutines.encryptionschemes.openssldecrypt_symkey(keystore + '/' + subdirA + '/private_key.pem', encrypted_symkey_path, passphrase)
    if (symkey == symkeyAB):
        print("Symmetric key exchange successful")
    # start a thread to receive the encrypted message
    encrypted_message_result = []
    receive_thread = threading.Thread(target=receive_message_thread, args=('localhost', PORT_B, encrypted_message_result))
    receive_thread.start()
    time.sleep(1)
    # user B encrypts a message using the symmetric key and sends it to user A
    message1 = "KNIGHTS SAY NI"
    encryptedAB = subroutines.encryptionschemes.opensslSymmetric(message1, symkey, encrypt=True)
    # send the encrypted message to user A
    send_message(encryptedAB, 'localhost', PORT_B)
    # wait for the thread to finish and get the result
    receive_thread.join()
    encrypted_message = encrypted_message_result[0]
    # user A decrypts the message using the symmetric key
    decryptedAB = subroutines.encryptionschemes.opensslSymmetric(encrypted_message, symkeyAB, encrypt=False)
    if (message1 == decryptedAB):
        print("Symmetric encryption/decryption successful")

# ---------------------------- #

    # TASK 3: Create a self-signed Certificate Authority (CA) and use it to sign a public key.
    subdirCA = 'CA'
    passphraseCA = "5678"
    certificatesdir = '../certificates'
    # generate a self-signed certificate for the CA
    subroutines.certificate.genCertificateSelfSigned(passphrase=passphraseCA, keystore=keystore + '/' + subdirCA, certificatesdir=certificatesdir + '/' + "CA", commonname="CA", emailaddress="ca@gmail.com", country="US", stateorprovince="CA", locality="San Francisco", organizationname="UC Berkeley", organizationunit="EECS", serialnumber=1111)
    # generate a certificate signing request (CSR) for user A
    subroutines.certificate.genCertificateRequest(keystore=keystore + '/' + subdirA, csrpath=certificatesdir + '/' + subdirA, commonname="A", emailaddress="a@gmail.com", country="IN", stateorprovince="KA", locality="Bangalore", organizationname="IISc", organizationunit="CSA")
    # sign the CSR using the CA's private key
    subroutines.certificate.signCertificateRequest(csrpath=certificatesdir + '/' + subdirA + '/csr.pem', ca_cert_path=certificatesdir + '/' + subdirCA + '/' + "selfsigned.crt", ca_key_path=keystore + '/' + subdirCA + '/' + "private_key.pem", certpath=certificatesdir + '/' + subdirA, serialnumber=1234)
    # verify the certificate using the CA's certificate
    subroutines.certificate.verifyCertificate(certpath=certificatesdir + '/' + subdirA + '/signed.crt', cacertpath=certificatesdir + '/' + subdirCA + '/' + "selfsigned.crt")

# ---------------------------- #

    # TASK 4: Use the previously created CA to sign and validate a public key.
    # user A submits a public key to the CA for signing, and the CA signs and returns the certificate
    subroutines.certificate.signPublicKey(user='A',publickeypath=keystore + '/' + subdirA + '/public_key.pem', cacertpath=certificatesdir + '/' + subdirCA + '/' + "selfsigned.crt", cakeypath=keystore + '/' + subdirCA + '/' + "private_key.pem", capassphrase=passphraseCA, certpath=certificatesdir + '/' + subdirA, serialnumber=1235)
    # validate the signed certificate using OpenSSL
    subroutines.certificate.verifyCertificate(certpath=certificatesdir + '/' + subdirA + '/signedpublickey.crt', cacertpath=certificatesdir + '/' + subdirCA + '/' + "selfsigned.crt")

# ---------------------------- #

    print("/----- MITM attack -----/")
    # TASK 5: Implement a MITM attack on a key exchange protocol
    """
    MITM attack: in the key exchange protocol, user Bob is generating a random symmetric key and encrypting it using user Alice's public key.
    Suppose an intruder Mallory intercepts Bob's request and convinces him to communicate using Mallory's public key instead of Alice's. 
    """
    mallory = 'Mallory'
    subdirM = 'M'
    passphraseM = '4321'
    PORT_M = 65435
    # generate a keypair for Mallory
    keys.generate_keypair(keystore + '/' + subdirM, passphraseM)
    # user B generates a symmetric key and encrypts it using user Mallory's public key
    symkeyB = keys.gensymkey() # the symmetric key with Bob
    subroutines.encryptionschemes.opensslencrypt_symkey(symkeyB, keystore + '/' + subdirM + '/public_key.pem', datadir + '/' + subdirM)
    # setup socket programming for user B to send the encrypted symmetric key to user A, but it is intercepted by Mallory
    encrypted_symkey_result = []
    receive_thread = threading.Thread(target=receive_message_thread, args=('localhost', PORT_M, encrypted_symkey_result))
    receive_thread.start()
    time.sleep(1)
    # send the encrypted symmetric key to user A's port (but it is intercepted by Mallory)
    send_message(datadir + '/' + subdirM + '/encrypted.bin', 'localhost', PORT_M)
    # wait for the thread to finish and get the result
    receive_thread.join()
    encrypted_symkey_path = encrypted_symkey_result[0]
    # Mallory decrypts the symmetric key using their private key
    symkeyM = subroutines.encryptionschemes.openssldecrypt_symkey(keystore + '/' + subdirM + '/private_key.pem', encrypted_symkey_path, passphraseM) # Mallory gets Bob's symmetric key
    if(symkeyB == symkeyM):
        print("Symmetric key exchange between Bob and Mallory successful")
    # Mallory encrypts the symmetric key using Alice's public key and sends it to Alice's port
    subroutines.encryptionschemes.opensslencrypt_symkey(symkeyM, keystore + '/' + subdirA + '/public_key.pem', datadir + '/' + subdirM)
    # start a thread to receive the encrypted symmetric key
    encrypted_symkey_result = []
    receive_thread = threading.Thread(target=receive_message_thread, args=('localhost', PORT_A, encrypted_symkey_result))
    receive_thread.start()
    time.sleep(1)
    # send the encrypted symmetric key to Alice
    send_message(datadir + '/' + subdirM + '/encrypted.bin', 'localhost', PORT_A)
    # wait for the thread to finish and get the result
    receive_thread.join()
    encrypted_symkeypath = encrypted_symkey_result[0]
    # Alice decrypts the symmetric key using their private key
    symkeyA = subroutines.encryptionschemes.openssldecrypt_symkey(keystore + '/' + subdirA + '/private_key.pem', encrypted_symkeypath, passphrase) # Alice decrypts the message and gets the same symmetric key
    if(symkeyM == symkeyA):
        print("Symmetric key exchange between Mallory and Alice successful")
    if(symkeyB == symkeyM and symkeyM == symkeyA):
        print("Mallory successfully intercepted the symmetric key exchange between Bob and Alice")
    print("Now Bob and Alice initiate communication using the symmetric key, and Mallory can read and modify the messages using the symmetric key")
    # Bob sends a message to Mallory's port encrypted using the symmetric key
    messageB = "Good morning, Alice"
    messageM = "Throw bomb"
    print("/----- Bob and Alice initiate communication with the symmetric key -----/")
    # Bob sends a message to Mallory thinking it is Alice
    # start a thread to receive the encrypted message
    encrypted_message_result = []
    receive_thread = threading.Thread(target=receive_message_thread, args=('localhost', PORT_M, encrypted_message_result))
    receive_thread.start()
    time.sleep(1)
    # Bob encrypts a message using the symmetric key and sends it to Mallory
    encryptedBM = subroutines.encryptionschemes.opensslSymmetric(messageB, symkeyB, encrypt=True)
    # send the encrypted message to Mallory
    send_message(encryptedBM, 'localhost', PORT_M)
    # wait for the thread to finish and get the result
    receive_thread.join()
    encrypted_message = encrypted_message_result[0]
    # user A decrypts the message using the symmetric key
    decryptedBM = subroutines.encryptionschemes.opensslSymmetric(encrypted_message, symkeyM, encrypt=False)
    print(f"\n\nMalloy intercepted Bob's message: '{decryptedBM}'")
    print(f"Mallory modifies the message to: '{messageM}', and sends it to Alice")
    # Mallory sends the modified message to Alice
    # start a thread to receive the encrypted message
    encrypted_message_result = []
    receive_thread = threading.Thread(target=receive_message_thread, args=('localhost', PORT_A, encrypted_message_result))
    receive_thread.start()
    time.sleep(1)
    # Bob encrypts a message using the symmetric key and sends it to Mallory
    encryptedMA = subroutines.encryptionschemes.opensslSymmetric(messageM, symkeyM, encrypt=True)
    # send the encrypted message to Mallory
    send_message(encryptedMA, 'localhost', PORT_A)
    # wait for the thread to finish and get the result
    receive_thread.join()
    encrypted_message = encrypted_message_result[0]
    # Alice decrypts the message using the symmetric key
    decryptedBM = subroutines.encryptionschemes.opensslSymmetric(encrypted_message, symkeyA, encrypt=False)
    print(f"Alice received the message: '{decryptedBM}'")

# ---------------------------- #

    # TASK 6: Implement the Needham-Schroeder protocol and demonstrate the Denning-Sacco attack
    # ------------- Needham-Schroeder ---------------- #
    print("/----- Needham-Schroeder protocol -----/")
    # A -> S : A, B, Na
    # S -> A : {Na, Kab, B, {Kab, A}Kbs}Kas
    # A -> B : {Kab, A}Kbs
    # B -> A : {Nb}Kab
    # A -> B : {Nb-1}Kab

    PORT_S = 65436
    PORT_B = 65437

    # Alice generates a random nonce Na
    Na = os.urandom(16)
    # start a thread to receive the message
    message_result = []
    receive_thread = threading.Thread(target=receive_message_thread, args=('localhost', PORT_S, message_result))
    receive_thread.start()
    time.sleep(1)
    # Alice sends to the trusted server A,B,Na
    send_message(f"A,B,{Na.hex()}", 'localhost', PORT_S)
    # wait for the thread to finish and get the result
    receive_thread.join()
    message = message_result[0]
    # the server retrieves the A,B,Na
    A, B, Na = message.decode().split(',')
    