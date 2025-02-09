from OpenSSL import crypto, SSL
import os
import getpass

def genCertificateSelfSigned(passphrase, keystore, certificatesdir, commonname,emailaddress,country,stateorprovince,locality,organizationname,organizationunit,serialnumber):
    if not os.path.exists(certificatesdir):
        os.makedirs(certificatesdir)
    if not os.path.exists(keystore):
        os.makedirs(keystore)
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)
    # Note: I have FILETYPE_PEM, because of this the private key is encrypted using the user's passphrase (so only the user has access to it from the keystore)
    privkey = crypto.dump_privatekey(crypto.FILETYPE_PEM, k, cipher="aes256", passphrase=passphrase.encode())
    pkey = crypto.dump_publickey(crypto.FILETYPE_PEM,k)
    validityStartinSeconds = 0
    validityEndinSeconds = 10*365*24*60*60 # I got this timing from a stack overflow example, so keeping it the same in case it is a
    cert = crypto.X509()
    cert.get_subject().C = country
    cert.get_subject().ST = stateorprovince
    cert.get_subject().L = locality
    cert.get_subject().O = organizationname
    cert.get_subject().OU = organizationunit
    cert.get_subject().CN = commonname
    cert.get_subject().emailAddress = emailaddress
    cert.set_serial_number(serialnumber)
    cert.gmtime_adj_notBefore(validityStartinSeconds)
    cert.gmtime_adj_notAfter(validityEndinSeconds)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha256') # self-sign this certificate using the private key
    print("ca certificate dir: ", certificatesdir)
    with open(certificatesdir + '/selfsigned.crt', 'wt') as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
    with open(keystore + '/private_key.pem', 'wt') as f:
        f.write(privkey.decode("utf-8"))
    with open(keystore + '/public_key.pem', 'wt') as f:
        f.write(pkey.decode("utf-8"))

def genCertificateRequest(keystore, csrpath, commonname, emailaddress, country, stateorprovince, locality, organizationname, organizationunit):
    if not os.path.exists(csrpath):
        os.makedirs(csrpath)
    # generate a certificate signing request (CSR) for user A signed by the CA
    req = crypto.X509Req()
    req.get_subject().CN = commonname
    req.get_subject().emailAddress = emailaddress
    req.get_subject().C = country
    req.get_subject().ST = stateorprovince
    req.get_subject().L = locality
    req.get_subject().O = organizationname
    req.get_subject().OU = organizationunit
    # load User A's private key
    with open(keystore + '/private_key.pem', 'rb') as f:
        passphrase = getpass.getpass("Enter pass phrase for" + keystore + '/private_key.pem:')
        priv_key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read(), passphrase=passphrase.encode())
    req.set_pubkey(priv_key) # set the user A's public key in the CSR
    req.sign(priv_key, 'sha256') # user A signs the CSR using their private key
    with open(csrpath + '/csr.pem', 'wt') as f:
        f.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, req).decode("utf-8"))
    
def signCertificateRequest(csrpath, ca_cert_path, ca_key_path, certpath, serialnumber):
    if not os.path.exists(certpath):
        os.makedirs(certpath)
    # load the CA's private key
    with open(ca_key_path, 'rb') as f:
        ca_passphrase = getpass.getpass("Enter pass phrase for" + ca_key_path + ':')
        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read(), passphrase=ca_passphrase.encode())
    # load the CA's certificate
    with open(ca_cert_path, 'rb') as f:
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
    # load the CSR
    with open(csrpath, 'rb') as f:
        req = crypto.load_certificate_request(crypto.FILETYPE_PEM, f.read())
    cert = crypto.X509()
    cert.set_serial_number(serialnumber)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
    cert.set_issuer(ca_cert.get_subject())
    cert.set_subject(req.get_subject())
    cert.set_pubkey(req.get_pubkey())
    cert.sign(ca_key, 'sha256')

    with open(certpath + '/signed.crt', 'wt') as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))

def verifyCertificate(certpath, cacertpath):
    with open(cacertpath, 'rb') as f:
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
    with open(certpath, 'rb') as f:
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
    store = crypto.X509Store()
    store.add_cert(ca_cert)
    store_ctx = crypto.X509StoreContext(store, cert)
    try:
        store_ctx.verify_certificate()
        print("Certificate verified")
    except Exception as e:
        print("Certificate verification failed")
        print(e)

def signPublicKey(user,publickeypath, cacertpath, cakeypath, capassphrase, certpath, serialnumber):
    if not os.path.exists(certpath):
        os.makedirs(certpath)
    with open(cakeypath, 'rb') as f:
        capassphrase = getpass.getpass("Enter pass phrase for" + cakeypath + ':')
        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read(), passphrase=capassphrase.encode())
    with open(cacertpath, 'rb') as f:
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
    with open(publickeypath, 'rb') as f:
        pubkey = crypto.load_publickey(crypto.FILETYPE_PEM, f.read())
    cert = crypto.X509()
    cert.set_serial_number(serialnumber)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
    cert.set_issuer(ca_cert.get_subject())
    cert.get_subject().CN = user
    cert.set_pubkey(pubkey)
    cert.sign(ca_key, 'sha256')
    with open(certpath + '/signedpublickey.crt', 'wt') as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
    print("Public key signed")
    