#!/usr/bin/env python3

import os
import sys
import time
import subprocess
import tempfile
import random
import atexit
from multiprocessing import Process
from http.server import HTTPServer, SimpleHTTPRequestHandler
import ssl
import datetime
from urllib.parse import urlsplit

import OpenSSL
print("imported OpenSSL module", OpenSSL)

import cryptography
print("imported cryptography module", cryptography)

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import pkcs7

sys.path.append(os.path.dirname(__file__) + "/..")
import aia
print("imported aia module", aia)

# pyppeteer/util.py
import gc
import socket
def get_free_port() -> int:
    """Get free port."""
    sock = socket.socket()
    #sock.bind(('localhost', 0))
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
    sock.close()
    del sock
    gc.collect()
    return port




from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import datetime

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa



def create_cert(name, issuer_cert=None, issuer_key=None, issuer_cert_url=None, is_leaf=False):

    """
    create a cryptography certificate and key.

    note: not pyopenssl cert
    """

    print(f"creating cert {repr(name)}")

    # https://cryptography.io/en/latest/x509/reference/#x-509-certificate-builder
    # https://stackoverflow.com/questions/56285000/python-cryptography-create-a-certificate-signed-by-an-existing-ca-and-export

    is_root = issuer_cert is None

    key = rsa.generate_private_key(
        public_exponent=65537,
        # key_size=2048 is slow, but python requires 2048 bit RSA keys
        # https://github.com/python/cpython/raw/main/Modules/_ssl.c
        # @SECLEVEL=2: security level 2 with 112 bits minimum security (e.g. 2048 bits RSA key)
        key_size=2048,
        backend=default_backend()
    )

    subject_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Texas"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Austin"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, name),
    ])

    issuer_name = subject_name if is_root else issuer_cert.subject

    cert = x509.CertificateBuilder()

    cert = cert.subject_name(subject_name)
    cert = cert.issuer_name(issuer_name)
    cert = cert.public_key(key.public_key())
    cert = cert.serial_number(x509.random_serial_number())
    cert = cert.not_valid_before(datetime.datetime.utcnow())
    cert = cert.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))

    # FIXME invalid CA certificate @ ctx.verify_certificate()

    # https://stackoverflow.com/a/72320618/10440128
    #if not is_leaf: # no. certificate signature failure
    if is_root:
        cert = cert.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)

    if issuer_cert_url:
        # add AIA extension
        # https://github.com/pyca/cryptography/raw/main/tests/x509/test_x509.py
        # aia = x509.AuthorityInformationAccess
        cert = cert.add_extension(x509.AuthorityInformationAccess([
            x509.AccessDescription(
                x509.oid.AuthorityInformationAccessOID.CA_ISSUERS,
                x509.UniformResourceIdentifier(issuer_cert_url),
            ),
        ]), critical=False)

    cert = cert.sign(key, hashes.SHA256(), default_backend())

    return cert, key



def run_http_server(args):

    host = args.get("host", "127.0.0.1")
    port = args.get("port", 80)
    ssl_cert_file = args.get("ssl_cert_file", None)
    ssl_key_file = args.get("ssl_key_file", None)
    root = args.get("root", "/tmp/www")
    #tmpdir = args.get("tmpdir", "/tmp")

    # https://stackoverflow.com/questions/22429648/ssl-in-python3-with-httpserver

    # SimpleHTTPRequestHandler serves files from workdir
    # this throws FileNotFoundError if root does not exist
    os.chdir(root)

    http_server = HTTPServer((host, port), SimpleHTTPRequestHandler)

    if ssl_cert_file and ssl_key_file:
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.check_hostname = False # If set to True, only the hostname that matches the certificate will be accepted
        # https://docs.python.org/3/library/ssl.html
        # The certfile string must be the path to a single file in PEM format containing the certificate
        # as well as any number of CA certificates needed to establish the certificate’s authenticity.
        # The keyfile string, if present, must point to a file containing the private key.
        ssl_context.load_cert_chain(ssl_cert_file, ssl_key_file)
        http_server.socket = ssl_context.wrap_socket(http_server.socket, server_side=True)

    http_server.serve_forever()



def run_test(tmpdir):

    print(f"using tempdir {repr(tmpdir)}")

    server_root = tmpdir + "/www"
    os.mkdir(server_root)

    # SSLContext.wrap_socket
    # Wrap an existing Python socket

    http_port = get_free_port()

    # create certs
    # TODO refactor ... create_cert_chain

    # FIXME invalid CA certificate @ ctx.verify_certificate()

    cert0, key0 = create_cert("root cert")
    with open(f"{server_root}/cert0", "wb") as f:
        # PEM format
        f.write(cert0.public_bytes(encoding=serialization.Encoding.PEM))
    url0 = f"http://127.0.0.1:{http_port}/cert0"

    cert1, key1 = create_cert("branch cert 1", cert0, key0, url0)
    with open(f"{server_root}/cert1", "wb") as f:
        # DER = ASN1 format
        f.write(cert1.public_bytes(encoding=serialization.Encoding.DER))
    url1 = f"http://127.0.0.1:{http_port}/cert1"

    # https://github.com/pyca/cryptography/raw/main/tests/hazmat/primitives/test_pkcs7.py
    # encoding = serialization.Encoding.PEM
    # encoding = serialization.Encoding.DER
    # p7 = pkcs7.serialize_certificates(certs, encoding)
    #f.write(cert2.public_bytes(encoding=serialization.Encoding.PEM))

    """
        f.write(pkcs7.serialize_certificates([cert2.to_cryptography()], Encoding.DER))
                                              ^^^^^^^^^^^^^^^^^^^^^
    AttributeError: 'cryptography.hazmat.bindings._rust.x509.Certificat' object has no attribute 'to_cryptography'

    fix: cert2 already is a cryptography cert

    nit: why "Certificat"? why not "Certificate" with a trailing "e"?
    """

    cert2, key2 = create_cert("branch cert 2", cert1, key1, url1)
    with open(f"{server_root}/cert2", "wb") as f:
        # PKCS7-DER format
        #f.write(pkcs7.serialize_certificates([cert2.to_cryptography()], Encoding.DER))
        f.write(pkcs7.serialize_certificates([cert2], Encoding.DER))
    url2 = f"http://127.0.0.1:{http_port}/cert2"

    cert3, key3 = create_cert("branch cert 3", cert2, key2, url2)
    with open(f"{server_root}/cert3", "wb") as f:
        # PKCS7-PEM format
        #f.write(pkcs7.serialize_certificates([cert3.to_cryptography()], Encoding.PEM))
        f.write(pkcs7.serialize_certificates([cert3], Encoding.PEM))
    url3 = f"http://127.0.0.1:{http_port}/cert3"

    # TODO test invalid url3 with invalid host or port

    cert4, key4 = create_cert("leaf cert", cert3, key3, url3, is_leaf=True)

    server_cert, server_key = cert4, key4

    https_server_cert_file = tempfile.mktemp(suffix=".pem", prefix="cert-", dir=tmpdir)
    with open(https_server_cert_file, "wb") as f:
        #cert_pem = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, server_cert) # pyopenssl
        cert_pem = server_cert.public_bytes(encoding=serialization.Encoding.PEM) # cryptography
        f.write(cert_pem)

    https_server_key_file = tempfile.mktemp(suffix=".pem", prefix="key-", dir=tmpdir)
    with open(https_server_key_file, "wb") as f:
        #key_pem = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, server_key) # pyopenssl
        # cryptography
        # https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
        key_pem = server_key.private_bytes(
            encoding=serialization.Encoding.PEM, # PEM, DER
            format=serialization.PrivateFormat.PKCS8, # TraditionalOpenSSL, OpenSSH, PKCS8
            encryption_algorithm=serialization.NoEncryption(), # BestAvailableEncryption, NoEncryption
        )
        f.write(key_pem)

    # start http server
    schema = "http"
    http_server_url = f"{schema}://127.0.0.1:{http_port}"
    print(f"starting {schema} server on {http_server_url}")
    http_server_args = dict(
        host="127.0.0.1",
        port=http_port,
        ssl_cert_file=None,
        ssl_key_file=None,
        root=server_root,
        #tmpdir=tmpdir,
    )
    http_server_process = Process(target=run_http_server, args=(http_server_args,))
    http_server_process.start()

    # start https server
    schema = "https"
    https_port = get_free_port()
    https_server_url = f"{schema}://127.0.0.1:{https_port}"
    print(f"starting {schema} server on {https_server_url}")
    https_server_args = dict(
        host="127.0.0.1",
        port=https_port,
        ssl_cert_file=https_server_cert_file,
        ssl_key_file=https_server_key_file,
        root=server_root,
        #tmpdir=tmpdir,
    )
    https_server_process = Process(target=run_http_server, args=(https_server_args,))
    https_server_process.start()

    def handle_exit():
        process_list = [
            http_server_process,
            https_server_process,
        ]
        for process in process_list:
            try:
                process.kill()
            except Exception:
                pass

    atexit.register(handle_exit)

    #print("todo run tests")
    #time.sleep(60)

    print("aia tests ...")

    print("creating aia_session")
    aia_session = aia.AIASession()

    def print_chain(cert_chain):
        if not cert_chain:
            print("  (empty)")
            return
        for (idx, cert) in enumerate(cert_chain):
            print(f"  {idx} subject: {cert.get_subject()}")
            print(f"    issuer: {cert.get_issuer()})")
            print(f'    fingerprint: {cert.digest("sha1")}')

    def print_cert(cert, label=None):
        if label:
            print(label + ":")
        if isinstance(cert, cryptography.x509.Certificate):
            # cryptography cert
            # https://cryptography.io/en/latest/x509/reference/
            print(f"  subject: {cert.subject}")
            print(f"    issuer: {cert.issuer})")
            print(f"    fingerprint: {cert.fingerprint(hashes.SHA256())}")
            return
        if isinstance(cert, OpenSSL.crypto.X509):
            # pyopenssl cert
            print(f"  subject: {cert.get_subject()}")
            print(f"    issuer: {cert.get_issuer()})")
            print(f'    fingerprint: {cert.digest("sha256")}')
            return
        raise ValueError("unknown cert type {type(cert)}")

    print("aia_session.aia_chase ...")

    print("-" * 80)

    test_name = "aia_session.aia_chase with untrusted root cert..."
    print(f"{test_name} ...")
    url = https_server_url
    url_parsed = urlsplit(url)
    host = url_parsed.netloc # note: netloc is host and port
    #print(f"parsed host {repr(host)} from url {repr(url)}")
    try:
        verified_cert_chain, missing_certs = aia_session.aia_chase(
            host, timeout=5, max_chain_depth=100,
        )
    except OpenSSL.crypto.X509StoreContextError as exc:
        # print("exc.errors", exc.errors)
        # exc.errors [19, 1, 'self-signed certificate in certificate chain']
        assert exc.errors[0] == 19
        cert = exc.certificate.to_cryptography()
        # assert different objects, but same content
        assert id(cert) != id(cert0) # no pointer equality
        assert cert == cert0 # "semantic equality"
        # assert that equality check is used
        cert_list = [cert0]
        assert cert in cert_list

    except Exception as exc:
        print("FIXME got unexpected exception:")
        print("exc.args", exc.args)
        print("exc.certificate", exc.certificate)
        print("exc.errors", exc.errors)
        print("exc str", str(exc))
        print("exc dir", dir(exc))
        raise
    print(f"{test_name} ok")

    print("-" * 80)

    test_name = "aia_session.add_trusted_root_cert with non-root cert"
    print(f"{test_name} ...")
    try:
        aia_session.add_trusted_root_cert(cert1)
        #raise ValueError("must be a CA cert")
    except ValueError as exc:
        assert str(exc) == "must be a CA cert"
    print(f"{test_name} ok")

    print("-" * 80)

    test_name = "aia_session.add_trusted_root_cert"
    print(f"{test_name} ...")
    assert aia_session.add_trusted_root_cert(cert0) == True
    assert aia_session.add_trusted_root_cert(cert0) == False # already exists
    print(f"{test_name} ok")

    print("-" * 80)

    test_name = "aia_session.aia_chase with trusted root cert"
    print(f"{test_name} ...")
    url = https_server_url
    url_parsed = urlsplit(url)
    host = url_parsed.netloc # note: netloc is host and port
    #print(f"parsed host {repr(host)} from url {repr(url)}")
    try:
        verified_cert_chain, missing_certs = aia_session.aia_chase(
            host, timeout=5, max_chain_depth=100,
        )
        print("verified_cert_chain"); print_chain(verified_cert_chain)
        print("missing_certs"); print_chain(missing_certs)
    except Exception as exc:
        print("FIXME got unexpected exception:")
        print("exc.args", exc.args)
        print("exc.certificate", exc.certificate)
        print("exc.errors", exc.errors)
        print("exc str", str(exc))
        print("exc dir", dir(exc))
        raise
        """
        FIXME got unexpected exception:
        exc.args ('self-signed certificate in certificate chain',)
        exc.certificate <OpenSSL.crypto.X509 object at 0x7f5876cf8b10>
        exc.errors [19, 2, 'self-signed certificate in certificate chain']
        exc str self-signed certificate in certificate chain
        """
    print(f"{test_name} ok")

    print("-" * 80)

    # TODO test
    # aia_session.remove_trusted_root_cert(cert0)

    print("aia_session.aia_chase done")

    """
    print("aia_session.cadata_from_url ...")
    url = https_server_url
    try:
        cadata = aia_session.cadata_from_url(url)
        print(cadata)
    except Exception as exc:
        print("FIXME got unexpected exception:")
        print("exc str", str(exc))
    print("aia_session.cadata_from_url done")
    """

    print("aia tests done")

    print(f"cleanup")
    handle_exit()

    print("done")



def main():

    # TODO check if dir exists
    main_tempdir = f"/run/user/{os.getuid()}"

    with (
            tempfile.TemporaryDirectory(
                prefix="python-aia-test",
                dir=main_tempdir,
                #ignore_cleanup_errors=False,
            ) as tmpdir,
        ):

        return run_test(tmpdir)



if __name__ == "__main__":

    main()
