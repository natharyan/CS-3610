import subprocess
import pickle
import os

def opensslencrypt(message, public_key_file, dir):
    if not os.path.exists(dir):
        os.makedirs(dir)
    input_file = os.path.join(dir, "plaintext.txt")
    output_file = os.path.join(dir, "encrypted.bin")
    with open(input_file, "w") as f:
        f.write(message)
    subprocess.run(["openssl", "pkeyutl", "-encrypt", "-pubin", "-inkey", public_key_file, "-in", input_file, "-out", output_file])
    os.remove(input_file)
    print(f"Message encrypted and saved to {output_file}")

def opensslencrypt_symmetric(symkey, public_key_file, dir):
    if not os.path.exists(dir):
        os.makedirs(dir)
    input_file = os.path.join(dir, "plaintext.txt")
    output_file = os.path.join(dir, "encrypted.bin")
    with open(input_file, "wb") as f:
        pickle.dump(symkey, f)
    subprocess.run(["openssl", "pkeyutl", "-encrypt", "-pubin", "-inkey", public_key_file, "-in", input_file, "-out", output_file])
    os.remove(input_file)
    print(f"Message encrypted and saved to {output_file}")
def openssldecrypt(privkeyfile, encrypted_file, passphrase, output_dir):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    output_file = os.path.join(output_dir, "decrypted.txt")
    result = subprocess.run(["openssl", "pkeyutl", "-decrypt", "-inkey", privkeyfile, "-in", encrypted_file], input=passphrase, text=True, capture_output=True)
    if result.returncode == 0:
        return result.stdout
    else:
        raise Exception("Decryption failed")