#!/usr/bin/env python3

import os
import sys
import time
import subprocess
import tempfile
import random
import atexit
import signal
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

    # https://cryptography.io/en/latest/x509/tutorial/
    # https://cryptography.io/en/latest/x509/reference/#x-509-certificate-builder
    # https://stackoverflow.com/questions/56285000/python-cryptography-create-a-certificate-signed-by-an-existing-ca-and-export
    # https://gist.github.com/major/8ac9f98ae8b07f46b208

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

    issuer_key = key if is_root else issuer_key

    cert = x509.CertificateBuilder()

    cert = cert.subject_name(subject_name)
    cert = cert.issuer_name(issuer_name)
    cert = cert.public_key(key.public_key())
    cert = cert.serial_number(x509.random_serial_number())
    cert = cert.not_valid_before(datetime.datetime.utcnow())
    cert = cert.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))

    cert = cert.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
        critical=False,
    )

    # https://stackoverflow.com/a/72320618/10440128
    #if is_root: # no. invalid CA certificate @ cert1

    if not is_leaf:
        cert = cert.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        cert = cert.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    else:
        cert = cert.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                issuer_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
            ),
            critical=False,
        )

    if is_leaf:
        cert = cert.add_extension(
            x509.ExtendedKeyUsage([
                x509.ExtendedKeyUsageOID.CLIENT_AUTH,
                x509.ExtendedKeyUsageOID.SERVER_AUTH,
            ]),
            critical=False,
        )

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

    # no. certificate signature failure
    #cert = cert.sign(key, hashes.SHA256(), default_backend())
    cert = cert.sign(issuer_key, hashes.SHA256(), default_backend())

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



def print_cert(cert, label=None, indent=""):
    if label:
        print(indent + label + ":")
    if isinstance(cert, cryptography.x509.Certificate):
        # cryptography cert
        # https://cryptography.io/en/latest/x509/reference/
        print(indent + f"  subject: {cert.subject}")
        print(indent + f"  issuer: {cert.issuer})")
        print(indent + f"  fingerprint: {cert.fingerprint(hashes.SHA256())}")
        return
    if isinstance(cert, OpenSSL.crypto.X509):
        # pyopenssl cert
        print(indent + f"  subject: {cert.get_subject()}")
        print(indent + f"  issuer: {cert.get_issuer()})")
        print(indent + f'  fingerprint: {cert.digest("sha256")}')
        return
    raise ValueError("unknown cert type {type(cert)}")



def print_chain(cert_chain):
    if not cert_chain:
        print("  (empty)")
        return
    for (idx, cert) in enumerate(cert_chain):
        print_cert(cert, f"cert {idx}", "  ")



def run_test(tmpdir):

    print(f"using tempdir {repr(tmpdir)}")

    server_root = tmpdir + "/www"
    os.mkdir(server_root)

    # SSLContext.wrap_socket
    # Wrap an existing Python socket

    http_port = get_free_port()

    # create certs
    # TODO refactor ... create_cert_chain

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
    http_server_process.stop = lambda: os.kill(http_server_process.pid, signal.SIGSTOP)
    http_server_process.cont = lambda: os.kill(http_server_process.pid, signal.SIGCONT)

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
    https_server_process.stop = lambda: os.kill(https_server_process.pid, signal.SIGSTOP)
    https_server_process.cont = lambda: os.kill(https_server_process.pid, signal.SIGCONT)

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

    print("aia tests ...")

    print("creating aia_session")
    aia_session = aia.AIASession()

    print("aia_session.aia_chase ...")

    print("-" * 80)

    # now aia_chase should fail
    test_name = "aia_session.aia_chase with untrusted root cert"
    print(f"{test_name} ...")
    url = https_server_url
    url_parsed = urlsplit(url)
    host = url_parsed.netloc # note: netloc is host and port
    #print(f"parsed host {repr(host)} from url {repr(url)}")
    try:
        verified_cert_chain, missing_certs = aia_session.aia_chase(
            host, timeout=1, max_chain_depth=100,
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
    print(f"{test_name} ok")

    print("-" * 80)

    test_name = "aia_session.add_trusted_root_cert with non-root cert"
    print(f"{test_name} ...")
    print_cert(cert1, "cert1")
    try:
        aia_session.add_trusted_root_cert(cert1)
        #raise ValueError("must be a CA cert")
        #raise ValueError("must be a self-signed cert")
    except ValueError as exc:
        expected_errors = [
            "must be a CA cert",
            "must be a self-signed cert",
        ]
        assert str(exc) in expected_errors
    print(f"{test_name} ok")

    print("-" * 80)

    test_name = "aia_session.add_trusted_root_cert"
    print(f"{test_name} ...")
    print_cert(cert0, "cert0")
    assert aia_session.add_trusted_root_cert(cert0) == True
    assert aia_session.add_trusted_root_cert(cert0) == False # already added
    print(f"{test_name} ok")

    print("-" * 80)

    # now aia_chase should work
    test_name = "aia_session.aia_chase with trusted root cert"
    print(f"{test_name} ...")
    url = https_server_url
    url_parsed = urlsplit(url)
    host = url_parsed.netloc # note: netloc is host and port
    #print(f"parsed host {repr(host)} from url {repr(url)}")
    try:
        verified_cert_chain, missing_certs = aia_session.aia_chase(
            host, timeout=1, max_chain_depth=100,
        )
        #print("verified_cert_chain"); print_chain(verified_cert_chain)
        #print("missing_certs"); print_chain(missing_certs)
    except Exception:
        raise
    print(f"{test_name} ok")

    print("-" * 80)

    test_name = "aia_session.remove_trusted_root_cert"
    print(f"{test_name} ...")
    print_cert(cert0, "cert0")
    assert aia_session.remove_trusted_root_cert(cert0) == True
    assert aia_session.remove_trusted_root_cert(cert0) == False # already removed
    print(f"{test_name} ok")

    print("-" * 80)

    # now aia_chase should fail again
    test_name = "aia_session.aia_chase with untrusted root cert"
    print(f"{test_name} ...")
    url = https_server_url
    url_parsed = urlsplit(url)
    host = url_parsed.netloc # note: netloc is host and port
    #print(f"parsed host {repr(host)} from url {repr(url)}")
    try:
        verified_cert_chain, missing_certs = aia_session.aia_chase(
            host, timeout=1, max_chain_depth=100,
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
    print(f"{test_name} ok")

    print("-" * 80)

    test_name = "aia_session.add_trusted_root_cert"
    print(f"{test_name} ...")
    print_cert(cert0, "cert0")
    assert aia_session.add_trusted_root_cert(cert0) == True
    assert aia_session.add_trusted_root_cert(cert0) == False # already added
    print(f"{test_name} ok")

    print("-" * 80)

    # now aia_chase should work again
    test_name = "aia_session.aia_chase with trusted root cert"
    print(f"{test_name} ...")
    url = https_server_url
    url_parsed = urlsplit(url)
    host = url_parsed.netloc # note: netloc is host and port
    #print(f"parsed host {repr(host)} from url {repr(url)}")
    try:
        # FIXME Exception: unable to get local issuer certificate. cert has no aia_ca_issuers
        verified_cert_chain, missing_certs = aia_session.aia_chase(
            host, timeout=1, max_chain_depth=100,
        )
        #print("verified_cert_chain"); print_chain(verified_cert_chain)
        #print("missing_certs"); print_chain(missing_certs)
    except Exception:
        raise
    print(f"{test_name} ok")

    print("-" * 80)

    # TODO test max_chain_depth=1

    test_name = "aia_session.aia_chase with stopped http server"
    print(f"{test_name} ...")
    # stop http server
    http_server_process.stop()
    # create new session to drop cache
    print("destroying aia_session")
    del aia_session
    print("creating aia_session")
    aia_session = aia.AIASession()
    # now aia_chase should fail
    url = https_server_url
    url_parsed = urlsplit(url)
    host = url_parsed.netloc # note: netloc is host and port
    #print(f"parsed host {repr(host)} from url {repr(url)}")
    try:
        verified_cert_chain, missing_certs = aia_session.aia_chase(
            host, timeout=1, max_chain_depth=100,
        )
        #print("verified_cert_chain"); print_chain(verified_cert_chain)
        #print("missing_certs"); print_chain(missing_certs)
    except TimeoutError:
        pass
    # FIXME BrokenPipeError from http server
    http_server_process.cont()
    print(f"{test_name} ok")

    print("-" * 80)

    test_name = "aia_session.aia_chase with stopped https server"
    print(f"{test_name} ...")
    # stop https server
    https_server_process.stop()
    # create new session to drop cache
    print("destroying aia_session")
    del aia_session
    print("creating aia_session")
    aia_session = aia.AIASession()
    # now aia_chase should fail
    url = https_server_url
    url_parsed = urlsplit(url)
    host = url_parsed.netloc # note: netloc is host and port
    #print(f"parsed host {repr(host)} from url {repr(url)}")
    try:
        verified_cert_chain, missing_certs = aia_session.aia_chase(
            host, timeout=1, max_chain_depth=100,
        )
        #print("verified_cert_chain"); print_chain(verified_cert_chain)
        #print("missing_certs"); print_chain(missing_certs)
    except TimeoutError:
        pass
    https_server_process.cont()
    print(f"{test_name} ok")

    print("-" * 80)

    # TODO test max_chain_depth=1

    '''
    except Exception as exc:
        print("FIXME got unexpected exception:")
        print("exc.args", exc.args)
        print("exc.certificate", exc.certificate)
        print_cert(exc.certificate, "exc.certificate")
        print("exc.errors", exc.errors)
        print("exc str", str(exc))
        print("exc dir", dir(exc))
        cert_path = f"/run/user/{os.getuid()}/python-aia-invalid-ca-cert.pem"
        print("writing", cert_path)
        cert_pem = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, exc.certificate)
        with open(cert_path, "wb") as f:
            f.write(cert_pem)
        raise
    '''

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
