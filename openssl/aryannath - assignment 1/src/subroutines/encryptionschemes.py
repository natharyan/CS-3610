import subprocess
import pickle
import os

# assymetric message encryption
def opensslencrypt(message, public_key_file, dir):
    if not os.path.exists(dir):
        os.makedirs(dir)
    input_file = os.path.join(dir, "plaintext.txt")
    output_file = os.path.join(dir, "encrypted.bin")
    with open(input_file, "w") as f:
        f.write(message)
    subprocess.run(["openssl", "pkeyutl", "-encrypt", "-pubin", "-inkey", public_key_file, "-in", input_file, "-out", output_file]) # using pkeyutl for asymmmetric encryption
    os.remove(input_file)
    print(f"Message encrypted and saved to {output_file}")

# assymetric message decryption
def openssldecrypt(privkeyfile, encrypted_file, passphrase):
    result = subprocess.run(["openssl", "pkeyutl", "-decrypt", "-inkey", privkeyfile, "-in", encrypted_file], input=passphrase, text=True, capture_output=True) # using pkeyutl for asymmmetric decryption
    if result.returncode == 0:
        return result.stdout
    else:
        raise Exception("Decryption failed")

# encrypt the symmetric key
def opensslencrypt_symkey(symkey, public_key_file, dir):
    if not os.path.exists(dir):
        os.makedirs(dir)
    input_file = os.path.join(dir, "plaintext.txt")
    output_file = os.path.join(dir, "encrypted.bin")
    with open(input_file, "wb") as f:
        f.write(symkey)
    subprocess.run(["openssl", "pkeyutl", "-encrypt", "-pubin", "-inkey", public_key_file, "-in", input_file, "-out", output_file]) # using pkeyutl for asymmmetric encryption
    os.remove(input_file)
    print(f"Message encrypted and saved to {output_file}")

# decrypt symmetric key
def openssldecrypt_symkey(privkeyfile, encrypted_file, passphrase):
    result = subprocess.run(["openssl", "pkeyutl", "-decrypt", "-inkey", privkeyfile, "-in", encrypted_file], input=passphrase.encode(), capture_output=True) # using pkeyutl for asymmmetric decryption
    if result.returncode == 0:
        return result.stdout
    else:
        raise Exception("Decryption failed") 

# encryption/decryption using the symmetric key
def opensslSymmetric(message, symkey,encrypt=True):
    if encrypt:
        if isinstance(message, bytes):
            message = message.decode()
        result = subprocess.run(["openssl", "enc", "-aes-256-cbc", "-pass", f"pass:{symkey.hex()}"], input=message.encode(), capture_output=True)
    else:
        result = subprocess.run(["openssl", "enc", "-d", "-aes-256-cbc", "-pass", f"pass:{symkey.hex()}"], input=message, capture_output=True)
    if result.returncode != 0:
        raise Exception("Encryption/Decryption failed")
    if encrypt:
        return result.stdout
    else:
        return result.stdout.decode()
