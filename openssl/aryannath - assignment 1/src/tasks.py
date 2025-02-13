import keys
import subroutines
from OpenSSL import crypto, SSL
import socket
import threading
import time
import os
import base64

import subroutines.certificate # user defined module
import subroutines.encryptionschemes # user defined module

PORT_A = 65432
PORT_B = 65433
PORT_CA = 65434
PORT_S = 65436
PORT_M = 65435
PORT_P = 65437

class ForwardingTable:
    def __init__(self):
        self.routes = {
            'A': {'port': PORT_A, 'server': None},
            'B': {'port': PORT_B, 'server': None},
            'CA': {'port': PORT_CA, 'server': None},
            'S': {'port': PORT_S, 'server': None},
            'M': {'port': PORT_M, 'server': None},
            'P': {'port': PORT_P, 'server': None}
        }
        self.hijacked_routes = {}
        self._initialize_servers()
        
    def _initialize_servers(self):
        """Initialize server sockets for each endpoint"""
        for user, info in self.routes.items():
            server = Server('localhost', info['port'])
            self.routes[user]['server'] = server
            print(f"Initialized server for {user} on port {info['port']}")
    
    def get_server(self, destination):
        """Get the server instance for a given destination"""
        if destination in self.hijacked_routes:
            hijacked_to = self.hijacked_routes[destination]
            print(f"[!] Route to {destination} is hijacked! Using {hijacked_to}'s server\n")
            return self.routes[hijacked_to]['server']
        return self.routes[destination]['server']
    
    def get_port(self, destination):
        """Get the port number for a given destination"""
        if destination in self.hijacked_routes:
            hijacked_to = self.hijacked_routes[destination]
            print(f"[!] Route to {destination} is hijacked! Using {hijacked_to}'s port\n")
            return self.routes[hijacked_to]['port']
        return self.routes[destination]['port']
    
    def hijack_route(self, target, redirect_to):
        """Hijack communications meant for target to redirect_to"""
        if target not in self.routes:
            raise ValueError(f"Unknown target: {target}")
        if redirect_to not in self.routes:
            raise ValueError(f"Unknown redirect destination: {redirect_to}")
            
        print(f"\n[!] Hijacking route: {target} -> {redirect_to}")
        self.hijacked_routes[target] = redirect_to
        
    def remove_hijack(self, target):
        """Remove a route hijacking"""
        if target in self.hijacked_routes:
            del self.hijacked_routes[target]
            print(f"\n[+] Removed hijack for {target}\n")
            
    def cleanup(self):
        """Close all server sockets"""
        for user, info in self.routes.items():
            if info['server']:
                info['server'].close()
                print(f"Closed server for {user}")

class Server:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        self.socket.listen()
        print(f"Server listening on {self.host}:{self.port}")

    def start(self):
        # start the server and wait for one connection
        conn, addr = self.socket.accept()
        print(f"Connected by {addr}")
        with conn:
            data = conn.recv(1024)
            return data

    def close(self):
        self.socket.close()

class Client:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def send_message(self, message):
        # send a message to the server
        self.socket.connect((self.host, self.port))
        if isinstance(message, str):
            self.socket.sendall(message.encode())
        else:
            self.socket.sendall(message)
        print(f"Sent message to {self.host}:{self.port}")
        self.socket.close()

def send_message(message, destination, forwarding_table):
    """Modified send_message function that uses forwarding table"""
    port = forwarding_table.get_port(destination)
    if port is None:
        raise ValueError(f"No route to destination: {destination}")
        
    client = Client('localhost', port)
    client.send_message(message)

def receive_message(destination, forwarding_table):
    """Receive a message using the forwarding table"""
    server = forwarding_table.get_server(destination)
    if server is None:
        raise ValueError(f"No server for destination: {destination}")
        
    data = server.start()
    return data

def receive_message_thread(destination, forwarding_table, result):
    """Thread function for receiving messages"""
    try:
        data = receive_message(destination, forwarding_table)
        result.append(data)
    except Exception as e:
        print(f"Error receiving message: {e}")

def symmetric_key_exchange(userA, userB, symkey, keystore, datadir, passphraseA, portA, portB):
    subdirB_A = f'{userB}-{userA}'  # user B to user A directory
    print(f"\nEncrypting the symmetric key using {userA}'s public key")
    # user B encrypts the symmetric key using user A's public key
    subroutines.encryptionschemes.opensslencrypt_symkey(symkey, keystore + '/' + userA + '/public_key.pem', datadir + '/' + subdirB_A)
    # start a thread to receive the encrypted symmetric key
    encrypted_symkey_result = []
    print(f"\nStarting a thread to receive the encrypted symmetric key on port {portA}")
    receive_thread = threading.Thread(target=receive_message_thread, args=('A',forwarding_table, encrypted_symkey_result))
    receive_thread.start()
    time.sleep(1)
    print(f"Sending the encrypted symmetric key to {userA} on port {portA}")
    # send the encrypted symmetric key to user A
    send_message(datadir + '/' + subdirB_A + '/encrypted.bin', 'A',forwarding_table)
    # wait for the thread to finish and get the result
    receive_thread.join()
    encrypted_symkey_path = datadir + '/' + subdirB_A + '/encrypted.bin'
    print(f"Received the encrypted symmetric key at {encrypted_symkey_path}")
    # user A decrypts the symmetric key using their private key
    print(f"Decrypting the symmetric key using {userA}'s private key\n")
    symkeyAB = subroutines.encryptionschemes.openssldecrypt_symkey(keystore + '/' + userA + '/private_key.pem', encrypted_symkey_path, passphraseA)
    if (symkey == symkeyAB):
        print("Symmetric key exchange successful")
    else:
        print("Symmetric key exchange failed")
    return symkeyAB


# port assignments, user A, user B, and CA. Communication: A <-> CA, B <-> A, B <-> CA
forwarding_table = ForwardingTable()

print("Port assignments:")
print(f"User A: localhost:{PORT_A}")
print(f"User B: localhost:{PORT_B}")
print(f"CA:{PORT_CA}")
print(f"Server:{PORT_S}")
print(f"Mallory:{PORT_M}")

keystore = '../keystore' # public database of keys (private keys are encrypted with a passphrase)
datadir = '../data'
certificatesdir = '../certificates'
subdirA = 'A' # user A
subdirCA = 'CA'
subdirB = 'B'
passphrase = "1234" # take as user input when retrieving the private key (stored by the server)
passphraseB = "1235"
passphraseCA = "5678"
passphraseM = '4321'


# ---------------------------- #

# TASK 1: generate 2048-bit RSA keypairs and encrypt/decrypt a message
def task1():
    print("\n\n/----- Task 1: Generate 2048-bit RSA keypairs and encrypt/decrypt a message -----/")
    global message
    keys.generate_keypair(keystore + '/' + subdirA, passphrase)
    message = "ATTACK AT DAWN"
    subroutines.encryptionschemes.opensslencrypt(message, keystore + '/' + subdirA + '/public_key.pem', datadir + '/' + subdirA)
    with open(datadir + '/' + subdirA + '/encrypted.bin', 'rb') as f:
        encrypted_message = f.read()
    print("Encrypted message:", encrypted_message)
    decrypted_text = subroutines.encryptionschemes.openssldecrypt(keystore + '/' + subdirA + '/private_key.pem', datadir + '/' + subdirA + '/encrypted.bin', passphrase)
    print(f"Decrypted message: {decrypted_text}")
    if (message == decrypted_text):
        print("Decryption successful")

# ---------------------------- #
# TASK 2: Establish a secure symmetric key exchange using OpenSSL
def task2():
    print("\n\n/----- Task 2: Establish a secure symmetric key exchange using OpenSSL -----/")
    global symkeyAB
    global symkey
    # user B generates a symmetric key and encrypts it using user A's public key
    print("\nUser B generates a symmetric key")
    symkey = keys.gensymkey()
    print("Initiating the symmetric key exchange between user A and user B using the public key of user A")
    symkeyAB = symmetric_key_exchange('A', 'B', symkey, keystore, datadir, passphrase, PORT_A, PORT_B)
    # start a thread to receive the encrypted message
    encrypted_message_result = []
    receive_thread = threading.Thread(target=receive_message_thread, args=('A', forwarding_table, encrypted_message_result))
    receive_thread.start()
    time.sleep(1)
    # user B encrypts a message using the symmetric key and sends it to user A
    message1 = "KNIGHTS SAY NI"
    print(f"\nUser B encrypts the message '{message1}' using the symmetric key and sends it to user A\n")
    encryptedAB = subroutines.encryptionschemes.opensslSymmetric(message1, symkey, encrypt=True)
    # send the encrypted message to user A
    send_message(encryptedAB, 'A',forwarding_table)
    # wait for the thread to finish and get the result
    receive_thread.join()
    encrypted_message = encrypted_message_result[0]
    # user A decrypts the message using the symmetric key
    print("\nUser A decrypts the received message using the symmetric key\n")
    decryptedAB = subroutines.encryptionschemes.opensslSymmetric(encrypted_message, symkeyAB, encrypt=False)
    if (message1 == decryptedAB):
        print("Symmetric encryption/decryption successful")
    else:
        print("Symmetric encryption/decryption failed")

# ---------------------------- #

# TASK 3: Create a self-signed Certificate Authority (CA) and use it to sign a public key.
def task3():
    print("\n\n/----- Task 3: Create a self-signed Certificate Authority (CA) and use it to sign a public key -----/")
    # generate a self-signed certificate for the CA
    print("\nGenerating a self-signed certificate for the CA")
    subroutines.certificate.genCertificateSelfSigned(passphrase=passphraseCA, keystore=keystore + '/' + subdirCA, certificatesdir=certificatesdir + '/' + "CA", commonname="CA", emailaddress="ca@gmail.com", country="US", stateorprovince="CA", locality="San Francisco", organizationname="UC Berkeley", organizationunit="EECS", serialnumber=1111)
    # generate a certificate signing request (CSR) for user A
    print("\nGenerating a certificate signing request (CSR) for user A")
    subroutines.certificate.genCertificateRequest(keystore=keystore + '/' + subdirA, csrpath=certificatesdir + '/' + subdirA, commonname="A", emailaddress="b@gmail.com", country="IN", stateorprovince="KA", locality="Bangalore", organizationname="IISc", organizationunit="CSA")
    # start a thread to receive the CSR
    print("Starting a thread to receive the CSR from user A")
    csr_result = []
    receive_thread = threading.Thread(target=receive_message_thread, args=('CA', forwarding_table, csr_result))
    receive_thread.start()
    time.sleep(1)
    # send the CSR to the CA
    print("\nSending the CSR to the CA")
    send_message(certificatesdir + '/' + subdirA + '/csr.pem', 'CA', forwarding_table)
    receive_thread.join()
    csr_path = csr_result[0]
    # sign the CSR using the CA's private key
    print("\nSigning the CSR using the CA's private key")
    subroutines.certificate.signCertificateRequest(csrpath=csr_path, ca_cert_path=certificatesdir + '/' + subdirCA + '/' + "selfsigned.crt", ca_key_path=keystore + '/' + subdirCA + '/' + "private_key.pem", certpath=certificatesdir + '/' + subdirA, serialnumber=1240)
    # start a thread to receive the signed certificate
    print("\nStarting a thread to receive the signed certificate from the CA")
    signed_cert_result = []
    receive_thread = threading.Thread(target=receive_message_thread, args=('A', forwarding_table, signed_cert_result))
    receive_thread.start()
    time.sleep(1)
    # send the signed certificate to user A
    print("\nSending the signed certificate to user A")
    send_message(certificatesdir + '/' + subdirA + '/signed.crt', 'A', forwarding_table)
    receive_thread.join()
    signed_cert_path = signed_cert_result[0]
    # verify the certificate using the CA's certificate
    print("\nVerifying the signed certificate using the CA's certificate")
    subroutines.certificate.verifyCertificate(certpath=signed_cert_path, cacertpath=certificatesdir + '/' + subdirCA + '/' + "selfsigned.crt")

# ---------------------------- #

# TASK 4: Use the previously created CA to sign and validate a public key.
def task4():
    print("\n\n/----- Task 4: Sign and validate a public key -----/")
    # user A submits a public key to the CA for signing, and the CA signs and returns the certificate
    print("User A submits a public key to the CA for signing")
    csr_result = []
    receive_thread = threading.Thread(target=receive_message_thread, args=('CA',forwarding_table, csr_result))
    receive_thread.start()
    time.sleep(1)
    # user A sends the CSR to the CA
    print("\nGenerating a certificate signing request (CSR) for user A")
    subroutines.certificate.genCertificateRequest(keystore=keystore + '/' + subdirA, csrpath=datadir + '/' + subdirA, commonname="A", emailaddress="a@gmail.com", country="IN", stateorprovince="KA", locality="Bangalore", organizationname="IISc", organizationunit="CSA")
    print("\nSending the CSR to the CA")
    send_message(datadir + '/' + subdirA + '/csr.pem', 'CA',forwarding_table)
    receive_thread.join()
    csr_path = csr_result[0]
    # CA signs the public key and returns the certificate
    print("\nCA signs the public key and returns the certificate")
    subroutines.certificate.signCertificateRequest(csrpath=csr_path, ca_cert_path=certificatesdir + '/' + subdirCA + '/' + "selfsigned.crt", ca_key_path=keystore + '/' + subdirCA + '/' + "private_key.pem", certpath=certificatesdir + '/' + subdirA, serialnumber=1235)
    signed_cert_result = []
    receive_thread = threading.Thread(target=receive_message_thread, args=('A',forwarding_table, signed_cert_result))
    receive_thread.start()
    time.sleep(1)
    # CA sends the signed certificate to user A
    print("\nSending the signed certificate to user A")
    send_message(certificatesdir + '/' + subdirA + '/signed.crt', 'A',forwarding_table)
    receive_thread.join()
    signed_cert_path = signed_cert_result[0]
    # validate the signed certificate using OpenSSL
    print("\nValidating the signed certificate using OpenSSL")
    subroutines.certificate.verifyCertificate(certpath=signed_cert_path, cacertpath=certificatesdir + '/' + subdirCA + '/' + "selfsigned.crt")

# ---------------------------- #

# TASK 5: Implement a MITM attack on a key exchange protocol
def task5():
    print("\n\n/----- Task 5: Implement a MITM")
    global symkeyB
    global symkeyM
    global symkeyA
    global messageB
    global messageM
    global mallory
    global subdirM
    """
    MITM attack: in the key exchange protocol, user Bob is generating a random symmetric key and encrypting it using user Alice's public key.
    Suppose an intruder Mallory intercepts Bob's request and convinces him to communicate using Mallory's public key instead of Alice's. 
    """
    print("\n\n/----- MITM attack -----/")
    print("Mallory is hijacking the server of the forwarding table to intercept the communication between Bob and Alice")
    mallory = 'Mallory'
    subdirM = 'M'
    # generate a keypair for Mallory
    print("Generating keypair for Mallory")
    keys.generate_keypair(keystore + '/' + subdirM, passphraseM)
    # user B generates a symmetric key and encrypts it using user Mallory's public key
    print("User B generates a symmetric key and encrypts it using Mallory's public key")
    symkeyB = keys.gensymkey() # the symmetric key with Bob
    subroutines.encryptionschemes.opensslencrypt_symkey(symkeyB, keystore + '/' + subdirM + '/public_key.pem', datadir + '/' + subdirM)
    # setup socket programming for user B to send the encrypted symmetric key to user A, but it is intercepted by Mallory
    
    print("Hijacking the forwarding table to redirect messages meant for Alice to Mallory")
    forwarding_table.hijack_route('A', 'M')

    encrypted_symkey_result = []
    receive_thread = threading.Thread(target=receive_message_thread, args=('A',forwarding_table, encrypted_symkey_result))
    receive_thread.start()
    time.sleep(1)
    # send the encrypted symmetric key to user Mallory's port address
    print(f"Bob -> Mallory: {datadir + '/' + subdirM + '/encrypted.bin'}")
    send_message(datadir + '/' + subdirM + '/encrypted.bin', 'A',forwarding_table)
    # wait for the thread to finish and get the result
    receive_thread.join()
    encrypted_symkey_path = encrypted_symkey_result[0]
    # Mallory decrypts the symmetric key using their private key
    print("Mallory decrypts the symmetric key using their private key")
    symkeyM = subroutines.encryptionschemes.openssldecrypt_symkey(keystore + '/' + subdirM + '/private_key.pem', encrypted_symkey_path, passphraseM) # Mallory gets Bob's symmetric key
    if(symkeyB == symkeyM):
        print("Symmetric key exchange between Bob and Mallory successful")
    # Mallory encrypts the symmetric key using Alice's public key and sends it to Alice's port

    forwarding_table.remove_hijack('A')

    print("Mallory encrypts the symmetric key using Alice's public key and sends it to Alice")
    subroutines.encryptionschemes.opensslencrypt_symkey(symkeyM, keystore + '/' + subdirA + '/public_key.pem', datadir + '/' + subdirM)
    # start a thread to receive the encrypted symmetric key
    encrypted_symkey_result = []
    receive_thread = threading.Thread(target=receive_message_thread, args=('A', forwarding_table, encrypted_symkey_result))
    receive_thread.start()
    time.sleep(1)
    # send the encrypted symmetric key to Alice
    print(f"Mallory -> Alice: {datadir + '/' + subdirM + '/encrypted.bin'}")
    send_message(datadir + '/' + subdirM + '/encrypted.bin', 'A', forwarding_table)
    # wait for the thread to finish and get the result
    receive_thread.join()
    encrypted_symkeypath = encrypted_symkey_result[0]
    # Alice decrypts the symmetric key using their private key
    print("Alice decrypts the symmetric key using their private key")
    symkeyA = subroutines.encryptionschemes.openssldecrypt_symkey(keystore + '/' + subdirA + '/private_key.pem', encrypted_symkeypath, passphrase) # Alice decrypts the message and gets the same symmetric key
    if(symkeyM == symkeyA):
        print("Symmetric key exchange between Mallory and Alice successful")
    if(symkeyB == symkeyM and symkeyM == symkeyA):
        print("Mallory successfully intercepted the symmetric key exchange between Bob and Alice")
    print("Now Bob and Alice initiate communication using the symmetric key, and Mallory can read and modify the messages using the symmetric key")
    # Bob sends a message to Mallory's port encrypted using the symmetric key
    messageB = "Good morning, Alice"
    messageM = "Throw bomb"
    print("\n\n/----- Bob and Alice initiate communication with the symmetric key -----/")
    # Bob sends a message to Mallory thinking it is Alice
    print("Bob sends a message to Mallory thinking it is Alice")
    # start a thread to receive the encrypted message

    print("Hijacking the forwarding table to redirect messages meant for Alice to Mallory")
    forwarding_table.hijack_route('A', 'M')

    encrypted_message_result = []
    receive_thread = threading.Thread(target=receive_message_thread, args=('A',forwarding_table, encrypted_message_result))
    receive_thread.start()
    time.sleep(1)
    # Bob encrypts a message using the symmetric key and sends it to Mallory
    encryptedBM = subroutines.encryptionschemes.opensslSymmetric(messageB, symkeyB, encrypt=True)
    # send the encrypted message to Mallory
    print(f"Bob -> Mallory: {encryptedBM.hex()}")
    send_message(encryptedBM, 'M', forwarding_table)
    # wait for the thread to finish and get the result
    receive_thread.join()
    encrypted_message = encrypted_message_result[0]
    # Mallory decrypts the message using the symmetric key
    decryptedBM = subroutines.encryptionschemes.opensslSymmetric(encrypted_message, symkeyM, encrypt=False)
    print(f"\n\nMallory intercepted Bob's message: '{decryptedBM}'")
    print(f"Mallory modifies the message to: '{messageM}', and sends it to Alice\n\n")
    # Mallory sends the modified message to Alice
    print("Mallory sends the modified message to Alice")

    forwarding_table.remove_hijack('A')

    # start a thread to receive the encrypted message
    encrypted_message_result = []
    receive_thread = threading.Thread(target=receive_message_thread, args=('A',forwarding_table, encrypted_message_result))
    receive_thread.start()
    time.sleep(1)
    # Mallory encrypts a message using the symmetric key and sends it to Alice
    encryptedMA = subroutines.encryptionschemes.opensslSymmetric(messageM, symkeyM, encrypt=True)
    # send the encrypted message to Alice
    print(f"Mallory -> Alice: {encryptedMA.hex()}")
    send_message(encryptedMA, 'A', forwarding_table)
    # wait for the thread to finish and get the result
    receive_thread.join()
    encrypted_message = encrypted_message_result[0]
    # Alice decrypts the message using the symmetric key
    decryptedBM = subroutines.encryptionschemes.opensslSymmetric(encrypted_message, symkeyA, encrypt=False)
    print(f"Alice received the message: '{decryptedBM}'")

# ---------------------------- #

# TASK 6: Implement the Needham-Schroeder protocol and demonstrate the Denning-Sacco attack (slides)
def task6slides():
    global Kab
    global subdirS
    global passphraseS
    
    print('\n\n/----- Denning-Sacco protocol -----/')
    # A -> S : A, B
    # S -> A : C(A), C(B)
    # A -> B : C(A), C(B), {{TA,Kab}Ka-1}Kb
    subdirS = 'S'
    passphraseS = '8765'
    keys.generate_keypair(keystore + '/' + subdirS, passphraseS)
    keys.generate_keypair(keystore + '/' + subdirA, passphrase)
    keys.generate_keypair(keystore + '/' + subdirB, passphrase)
    Kab = keys.gensymkey()
    print("\nInitiating Denning-Sacco protocol...")
    message_resultAS = []
    receive_thread = threading.Thread(target=receive_message_thread, args=('S', forwarding_table, message_resultAS))
    receive_thread.start()
    time.sleep(1)
    print("Alice -> Server: A,B")
    send_message("A,B", 'S', forwarding_table)
    receive_thread.join()
    message_resultAS = message_resultAS[0]
    message_result = []
    receive_thread = threading.Thread(target=receive_message_thread, args=('A', forwarding_table, message_result))
    receive_thread.start()
    time.sleep(1)
    print("Server -> Alice: C(A), C(B)")
    A, B = message_resultAS.decode().split(',')
    with open(certificatesdir + '/' + A.strip() + '/signed.crt', 'rb') as f:
        CA = f.read()
    with open(certificatesdir + '/' + B.strip() + '/signed.crt', 'rb') as f:
        CB = f.read()
        
    send_message(f"{CA.hex()},{CB.hex()}", 'A', forwarding_table)
    receive_thread.join()
    TA = str(int(time.time()))
    subroutines.encryptionschemes.opensslencrypt(f"{TA},{Kab.hex()}", keystore + '/' + subdirA + '/private_key.pem',datadir + '/' + subdirA)
    with open(datadir + '/' + subdirA + '/encrypted.bin', 'rb') as f:
        signed_data = f.read()
    subroutines.encryptionschemes.opensslencrypt(signed_data.hex(),keystore + '/' + subdirB + '/public_key.pem',datadir + '/' + subdirA)
    with open(datadir + '/' + subdirA + '/encrypted.bin', 'rb') as f:
        final_message = f.read()
    message_result = []
    receive_thread = threading.Thread(target=receive_message_thread, args=('B', forwarding_table, message_result))
    receive_thread.start()
    time.sleep(1)
    print("Alice -> Bob: C(A), C(B), {{TA,Kab}Ka-1}Kb")
    send_message(f"{CA.hex()},{CB.hex()},{final_message.hex()}", 'B', forwarding_table)
    receive_thread.join()
    print("\nDenning-Sacco protocol completed")
    # ------------- Denning-Sacco Attack ---------------- #
    print("\n/----- Denning-Sacco Attack Demonstration -----/")
    print("B wants to masquerade as A to P")
    message_result = []
    receive_thread = threading.Thread(target=receive_message_thread, args=('S', forwarding_table, message_result))
    receive_thread.start()
    time.sleep(1)
    print("B -> Server: B,P")
    send_message("B,P", 'S', forwarding_table)
    receive_thread.join()
    with open(certificatesdir + '/' + subdirB + '/signed.crt', 'rb') as f:  # Using B's cert as P for simulation
        CP = f.read()
    # B can reuse the captured {{TA,Kab}Ka-1} and re-encrypt it with P's public key
    captured_data = final_message
    subdirP = 'P'
    passphraseP = '1236'
    keys.generate_keypair(keystore + '/' + subdirP, passphraseP)
    # B re-encrypts the captured data with P's public key
    subroutines.encryptionschemes.opensslencrypt(captured_data.hex(),keystore + '/' + subdirP + '/public_key.pem',datadir + '/' + subdirP)
    with open(datadir + '/' + subdirP + '/encrypted.bin', 'rb') as f:
        reencrypted_data = f.read()
    # B sends the forged message to P
    message_result = []
    receive_thread = threading.Thread(target=receive_message_thread, args=('P', forwarding_table, message_result))
    receive_thread.start()
    time.sleep(1)
    print("B -> P: C(B), C(P), {{TA,Kab}Ka-1}Kp")
    send_message(f"{CB.hex()},{CP.hex()},{reencrypted_data.hex()}", 'B', forwarding_table)
    receive_thread.join()


# TASK 6: Implement the Needham-Schroeder protocol and demonstrate the Denning-Sacco attack (this is based on the wikipedia page for the Needham-Schroeder protocol)
def task6():
    global Kab
    global Kas
    global Kbs
    global subdirS
    global passphraseS
    
    # ------------- Needham-Schroeder ---------------- #
    print("\n\n/----- Needham-Schroeder protocol -----/")
    # A -> S : A, B, Na
    # S -> A : {Na, Kab, B, {Kab, A}Kbs}Kas
    # A -> B : {Kab, A}Kbs
    # B -> A : {Nb}Kab
    # A -> B : {Nb-1}Kab

    Kab = keys.gensymkey()
    Kas = keys.gensymkey()
    Kbs = keys.gensymkey()

    # generate a keypair for the server
    subdirS = 'S'
    passphraseS = '8765'
    keys.generate_keypair(keystore + '/' + subdirS, passphraseS)

    # symmetric key exchange between server and Alice
    symkeyAS = symmetric_key_exchange('A', 'S', Kas, keystore, datadir, passphrase, PORT_S, PORT_A)
    if(symkeyAS == Kas):
        print("Symmetric key exchange between server and Alice successful")
    else:
        print("Symmetric key exchange between server and Alice failed")
    # symmetric key exchange between server and Bob
    symkeyBS = symmetric_key_exchange('A', 'S', Kbs, keystore, datadir, passphrase, PORT_S, PORT_B)
    if(symkeyBS == Kbs):
        print("Symmetric key exchange between server and Bob successful")
    else:
        print("Symmetric key exchange between server and Bob failed")

    # Alice generates a random nonce Na
    Na = os.urandom(16)
    # start a thread to receive the message
    message_result = []
    receive_thread = threading.Thread(target=receive_message_thread, args=('S', forwarding_table, message_result))
    receive_thread.start()
    time.sleep(1)
    # Alice sends to the trusted server A,B,Na
    print(f"Alice -> Server: A,B,{Na.hex()}")
    send_message(f"A,B,{Na.hex()}", 'S', forwarding_table)
    # wait for the thread to finish and get the result
    receive_thread.join()
    message = message_result[0]
    # the server retrieves the A,B,Na
    A, B, Na = message.decode().split(',')
    # convert Na to bytes (Na = os.urandom(16))
    Na = bytes.fromhex(Na)

    # S sends to Alice {Na, Kab, B, {Kab, A}Kbs}Kas
    Spacket = subroutines.encryptionschemes.opensslSymmetric(f"{Na.hex()},{Kab.hex()},{B},{subroutines.encryptionschemes.opensslSymmetric(f'{Kab.hex()},{A}', Kbs, encrypt=True).hex()}", Kas, encrypt=True)
    print(f"Server -> Alice: {Spacket.hex()}")
    # start a thread to receive the message
    message_result = []
    receive_thread = threading.Thread(target=receive_message_thread, args=('A', forwarding_table, message_result))
    receive_thread.start()
    time.sleep(1)
    # server send the packet to Alice
    send_message(Spacket, 'A', forwarding_table)
    # wait for the thread to finish and get the result
    receive_thread.join()
    message = message_result[0]
    # Alice decrypts the packet
    packet = subroutines.encryptionschemes.opensslSymmetric(message, Kas, encrypt=False)
    # Alice retrieves Na, Kab, B, {Kab, A}Kbs
    Na, Kab, B, KabA = packet.split(',')
    # convert Kab to bytes
    Kab = bytes.fromhex(Kab)
    # Alice sends to Bob {Kab, A}Kbs
    print(f"Alice -> Bob: {KabA}")
    # start a thread to receive the message
    message_result = []
    receive_thread = threading.Thread(target=receive_message_thread, args=('B', forwarding_table, message_result))
    receive_thread.start()
    time.sleep(1)
    # send {Kab, A}Kbs to Bob
    send_message(bytes.fromhex(KabA), 'B', forwarding_table)
    # wait for the thread to finish and get the result
    receive_thread.join()
    message = message_result[0]
    # Bob decrypts the packet
    packet = subroutines.encryptionschemes.opensslSymmetric(message, Kbs, encrypt=False)
    Kab, A = packet.split(',')
    # convert Kab to bytes
    Kab = bytes.fromhex(Kab)
    # Bob generates a random nonce Nb
    Nb = os.urandom(16)
    # Bob sends to Alice {Nb}Kab
    print(f"Bob -> Alice: ({Nb.hex()})Kab")
    # start a thread to receive the message
    message_result = []
    receive_thread = threading.Thread(target=receive_message_thread, args=('A', forwarding_table, message_result))
    receive_thread.start()
    time.sleep(1)
    # Bob send {Nb}Kab to Alice
    send_message(subroutines.encryptionschemes.opensslSymmetric(f"{Nb.hex()}", Kab, encrypt=True), 'A', forwarding_table)
    # wait for the thread to finish and get the result
    receive_thread.join()
    message = message_result[0]
    # Alice decrypts the packet
    packet = subroutines.encryptionschemes.opensslSymmetric(message, Kab, encrypt=False)
    Nb = packet
    Nb = bytes.fromhex(Nb)
    # convert Nb to int
    Nb = int.from_bytes(Nb, byteorder='big')
    Nbsend = Nb - 1
    # convert Nbsend to bytes
    Nbsend = Nbsend.to_bytes(16, byteorder='big')
    # Alice sends to Bob {Nb-1}Kab
    print(f"Alice -> Bob: ({Nbsend.hex()})Kab")
    # start a thread to receive the message
    message_result = []
    receive_thread = threading.Thread(target=receive_message_thread, args=('B', forwarding_table, message_result))
    receive_thread.start()
    time.sleep(1)
    # send {Nb-1}Kab to Bob
    send_message(subroutines.encryptionschemes.opensslSymmetric(f"{Nbsend.hex()}", Kab, encrypt=True), 'B', forwarding_table)
    # wait for the thread to finish and get the result
    receive_thread.join()
    message = message_result[0]
    # Bob decrypts the packet
    packet = subroutines.encryptionschemes.opensslSymmetric(message, Kab, encrypt=False)
    Nb1 = packet
    Nb1 = bytes.fromhex(Nb1)
    Nb1 = int.from_bytes(Nb1, byteorder='big')
    if(Nb1 == Nb - 1):
        print("Needham-Schroeder protocol successful")
    else:
        print("Needham-Schroeder protocol failed")
    # ------------- Denning-Sacco ---------------- #
    print("\n\n/----- Denning-Sacco attack -----/")

    print("Mallory gets access to Kab and the ticket {Kab, A}Kbs")
    print("Mallory can now impersonate Alice to Bob")
    message_result = []
    receive_thread = threading.Thread(target=receive_message_thread, args=('B', forwarding_table, message_result))
    receive_thread.start()
    time.sleep(1)
    # Mallory sends the ticket to Bob
    print(f"Mallory -> Bob: {KabA}")
    send_message(bytes.fromhex(KabA), 'B', forwarding_table)
    # wait for the thread to finish and get the result
    receive_thread.join()
    message = message_result[0]
    # Bob decrypts the packet
    packet = subroutines.encryptionschemes.opensslSymmetric(message, Kbs, encrypt=False)
    Kab, A = packet.split(',')
    # convert Kab to bytes
    Kab = bytes.fromhex(Kab)
    # Bob generates a random nonce Nb
    Nb = os.urandom(16)
    # Bob sends to Alice {Nb}Kab
    print(f"Bob -> Mallory: ({Nb.hex()})Kab")
    # start a thread to receive the message
    message_result = []
    receive_thread = threading.Thread(target=receive_message_thread, args=('A', forwarding_table, message_result))
    receive_thread.start()
    time.sleep(1)
    # Bob send {Nb}Kab to Alice
    send_message(subroutines.encryptionschemes.opensslSymmetric(f"{Nb.hex()}", Kab, encrypt=True), 'A', forwarding_table)
    # wait for the thread to finish and get the result
    receive_thread.join()
    message = message_result[0]
    # Alice decrypts the packet
    packet = subroutines.encryptionschemes.opensslSymmetric(message, Kab, encrypt=False)
    Nb = packet
    Nb = bytes.fromhex(Nb)
    # convert Nb to int
    Nb = int.from_bytes(Nb, byteorder='big')
    Nbsend = Nb - 1
    # convert Nbsend to bytes
    Nbsend = Nbsend.to_bytes(16, byteorder='big')
    # Alice sends to Bob {Nb-1}Kab
    print(f"Mallory -> Bob: ({Nbsend.hex()})Kab")
    # start a thread to receive the message
    message_result = []
    receive_thread = threading.Thread(target=receive_message_thread, args=('B', forwarding_table, message_result))
    receive_thread.start()
    time.sleep(1)
    # send {Nb-1}Kab to Bob
    send_message(subroutines.encryptionschemes.opensslSymmetric(f"{Nbsend.hex()}", Kab, encrypt=True), 'B', forwarding_table)
    # wait for the thread to finish and get the result
    receive_thread.join()
    message = message_result[0]
    # Bob decrypts the packet
    packet = subroutines.encryptionschemes.opensslSymmetric(message, Kab, encrypt=False)
    Nb1 = packet
    Nb1 = bytes.fromhex(Nb1)
    Nb1 = int.from_bytes(Nb1, byteorder='big')
    if(Nb1 == Nb - 1):
        print("Mallory has successfully masqueraded as Alice to Bob")
    else:
        print("Mallory failed to masquerade as Alice to Bob")