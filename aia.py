import os
import sys
from contextlib import ExitStack
from functools import lru_cache, partial
import logging
import re
import socket
import ssl
from tempfile import NamedTemporaryFile
from urllib.request import urlopen, Request
from urllib.parse import urlsplit

# pyopenssl
import OpenSSL

# https://cryptography.io/en/latest/x509/
import cryptography
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import pkcs7

import certifi


__version__ = "0.2.0"

# logging.getLogger('aia').setLevel(logging.DEBUG)
# import aia
logger = logging.getLogger(__name__)

logger.setLevel(logging.DEBUG) # FIXME not working
logger.debug = print

logger.debug(f"imported aia {__version__}")

DEFAULT_USER_AGENT = f"Python-aia/{__version__}"


class DownloadError(Exception):
    pass


class AIAError(Exception):
    pass


class AIASchemeError(AIAError):
    pass


class AIADownloadError(AIAError, DownloadError):
    pass


class InvalidCAError(AIAError):
    pass


class CachedMethod:
    """
    A ``functools.lru_cache`` cache decorator for methods,
    but applied on each bound method (i.e., in the instance)
    in order to avoid memory leak issues relating to
    caching an unbound method directly from the owner class.
    """

    def __init__(self, maxsize=128, typed=False):
        if callable(maxsize):
            self.func = maxsize
            self.maxsize = None
        else:
            self.maxsize = maxsize
        self.typed = typed

    def __call__(self, func):
        self.func = func
        return self

    def __set_name__(self, owner, name):
        self.name = name

    def __get__(self, instance, owner):
        bound_method = partial(self.func, instance)
        result = lru_cache(self.maxsize, self.typed)(bound_method)
        setattr(instance, self.name, result)
        return result


def get_cn_of_name(name):
    # https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Name
    for attr in name:
        if attr.rfc4514_attribute_name == "CN":
            return attr.value


def get_ca_issuers_of_cert(cert):
    # convert cert from pyopenssl to cryptography
    cert = cert.to_cryptography()
    try:
        aia_extension = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
    except x509.extensions.ExtensionNotFound:
        return []
    # https://cryptography.io/en/latest/x509/reference/#cryptography.x509.AccessDescription
    ca_issuers = []
    for access_description in aia_extension.value:
        if access_description.access_method._name == "caIssuers":
            ca_issuers.append(access_description.access_location.value)
    return ca_issuers


def openssl_get_cert_info(cert_der):
    """
    Get issuer, subject and AIA CA issuers (``aia_ca_issuers``)
    from a DER certificate.
    """
    cert = x509.load_der_x509_certificate(cert_der)
    cert_info = dict(
        issuer = get_cn_of_name(cert.issuer),
        subject = get_cn_of_name(cert.subject),
        aia_ca_issuers = get_ca_issuers_of_cert(cert),
    )
    return cert_info


class AIASession:

    def __init__(
            self,
            user_agent=DEFAULT_USER_AGENT,
            cache_db=None,
            cache_dir=None,
        ):
        """
        Create a new session.
        Downloaded certificates are cached in cache_dir or cache_db.
        """
        logger.debug("creating AIASession")
        self.user_agent = user_agent
        self.cache_db = cache_db
        self.cache_db_con = None
        self.cache_db_cur = None
        self.cache_dir = cache_dir
        self._context = OpenSSL.SSL.Context(method=OpenSSL.SSL.TLS_CLIENT_METHOD)
        self._context.load_verify_locations(cafile=certifi.where())
        self._cadata_from_host_regex = dict()

    @CachedMethod
    def get_host_cert_chain(self, host, timeout=5):
        """
        Get the certificate chain from the target host,
        without checking it, without fetching missing certs.
        """
        logger.debug(f"Downloading TLS certificate chain from {host}")
        port = 443
        if ':' in host:
            host, port = host.split(':')
            port = int(port)
        # https://stackoverflow.com/a/67212703/10440128
        conn = OpenSSL.SSL.Connection(
            self._context,
            socket=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        )
        conn.settimeout(timeout)
        # NOTE this block can throw OpenSSL.SSL.Error ...
        conn.connect((host, port))
        conn.setblocking(1)
        conn.set_tlsext_host_name(host.encode())
        conn.do_handshake()
        full_cert_chain = conn.get_peer_cert_chain()
        verified_cert_chain = conn.get_verified_chain()
        conn.close()
        if len(verified_cert_chain) == len(full_cert_chain):
            # rest_cert_chain is empty
            # this does not mean that the chain is valid
            # the server can return only 1 cert
            return verified_cert_chain, None
        rest_cert_chain = full_cert_chain[len(verified_cert_chain):]
        return verified_cert_chain, rest_cert_chain

    def _init_cache_db(self):
        if self.cache_db_con:
            return
        import sqlite3
        os.makedirs(os.path.dirname(self.cache_db), exist_ok=True)
        self.cache_db_con = sqlite3.connect(self.cache_db)
        self.cache_db_cur = self.cache_db_con.cursor()
        # note: we do not store the cert's fetch time for better privacy
        # TODO use nssdb format? https://github.com/milahu/nssdb-py
        # how does chrome cache the fetched certs?
        query = "\n".join([
            "CREATE TABLE certs (",
            "  url TEXT PRIMARY KEY,",
            "  cert_der BLOB",
            ")",
        ])
        try:
            self.cache_db_cur.execute(query)
            logger.debug(f"created table certs in cache_db {self.cache_db}")
        except sqlite3.OperationalError as exc:
            if str(exc) != "table certs already exists":
                raise

    def _read_cert_cache(self, url_parsed):
        if not self.cache_dir and not self.cache_db:
            # caching is disabled
            return
        url = url_parsed.geturl()
        # prefer cache_db
        if self.cache_db:
            self._init_cache_db()
            query = "select cert_der from certs where url = ?"
            args = (url,)
            cur = self.cache_db_cur.execute(query, args)
            row = cur.fetchone()
            if row:
                logger.debug(f"found cert in cache_db: {url}")
                cert_der = row[0]
                # no. here we need pyopenssl cert # TODO why?
                #cert = x509.load_der_x509_certificate(cert_der)
                cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_der)
                return cert
        if self.cache_dir:
            cache_path = self.cache_dir + "/" + url_parsed.netloc + url_parsed.path
            if os.path.exists(cache_path):
                logger.debug(f"found cert in cache_dir: {url}")
                with open(cache_path, "rb") as f:
                    cert_der = f.read()
                # no. here we need pyopenssl cert # TODO why?
                #cert = x509.load_der_x509_certificate(cert_der)
                cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_der)
                return cert
        logger.debug("not found cert in cache: {url}")

    def _write_cert_cache(self, url_parsed, cert):
        if not self.cache_dir and not self.cache_db:
            # caching is disabled
            return
        url = url_parsed.geturl()
        cert_der = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
        if self.cache_db:
            logger.debug(f"adding cert to cache_db: {url}")
            self._init_cache_db()
            query = "insert into certs (url, cert_der) values (?, ?)"
            args = (url, cert_der)
            cur = self.cache_db_cur.execute(query, args)
            print("cur", cur)
            if cur.rowcount != 1:
                logger.warning(f"failed to add cert to cache_db: {url}")
            # write to disk
            self.cache_db_con.commit()
        if self.cache_dir:
            cache_path = self.cache_dir + "/" + url_parsed.netloc + url_parsed.path
            # check again if cache_path exists. can have multiple writers
            if not os.path.exists(cache_path):
                logger.debug(f"adding cert to cache_dir: {url}")
                os.makedirs(os.path.dirname(cache_path), exist_ok=True)
                with open(cache_path, "wb") as f:
                    f.write(cert_der)

    def _load_cert_from_bytes(self, cert_bytes):
        # TODO pyopenssl or cryptography
        # try to load DER = ASN1 format
        try:
            # no. here we need pyopenssl cert # TODO why?
            #cert = x509.load_der_x509_certificate(cert_der)
            cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_bytes)
            return cert
        except OpenSSL.crypto.Error:
            pass
        #except Exception as exc:
        #    print("exc", type(exc), exc)
        #    raise

        # try to load PKCS7 format
        # https://source.chromium.org/chromium/chromium/src/+/main:net/cert/internal/cert_issuer_source_aia.cc
        # https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/#pkcs7
        # ParseCertsFromCms

        # try to load PKCS7-DER format
        try:
            # FIXME AttributeError: module 'cryptography.hazmat.primitives.serialization' has no attribute 'pkcs7'. Did you mean: 'pkcs12'?
            # cryptography-42.0.5
            certs = pkcs7.load_der_pkcs7_certificates(cert_bytes)
            assert len(certs) == 1 # TODO
            cert = certs[0]
            # here we need pyopenssl cert # TODO why?
            cert = OpenSSL.crypto.X509.from_cryptography(cert)
            return cert
        except ValueError:
            # ValueError: Unable to parse PKCS7 data
            pass
        #except Exception as exc:
        #    print("exc", type(exc), exc)
        #    raise

        # try to load PKCS7-PEM format
        try:
            certs = pkcs7.load_pem_pkcs7_certificates(cert_bytes)
            assert len(certs) == 1 # TODO
            cert = certs[0]
            # here we need pyopenssl cert # TODO why?
            cert = OpenSSL.crypto.X509.from_cryptography(cert)
            return cert
        except ValueError:
            # ValueError: Unable to parse PKCS7 data
            pass
        #except Exception as exc:
        #    print("exc", type(exc), exc)
        #    raise

        # try to load PEM format
        try:
            cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_bytes)
            return cert
        except OpenSSL.crypto.Error:
            pass
        #try:
        #except Exception as exc:
        #    print("exc", type(exc), exc)
        #    raise

        # TODO more specific
        raise Exception(f"failed to parse cert from {url}. cert_bytes: {cert_bytes.hex()}")

    @CachedMethod
    def _get_ca_issuer_cert(self, url):
        """
        Get an intermediary DER (binary) certificate in the chain
        from a given URL which should had been found
        as the CA Issuer URI in the AIA extension
        of the previous "node" (certificate) of the chain.
        """
        url_parsed = urlsplit(url)
        if url_parsed.scheme != "http":
            # ERR_DISALLOWED_URL_SCHEME
            raise AIASchemeError("Invalid CA issuer certificate URI protocol")
        cert = self._read_cert_cache(url_parsed)
        if cert:
            return cert
        logger.debug(f"Downloading CA issuer certificate from {url}")
        req = Request(url=url, headers={"User-Agent": self.user_agent})
        with urlopen(req) as resp:
            if resp.status != 200:
                raise AIADownloadError(f"HTTP {resp.status} (CA Issuer Cert.)")
            cert_bytes = resp.read()
            # cert_bytes can have different formats: DER = ASN1, CMS = PKCS7 = P7B, PEM
            # https://tools.ietf.org/html/rfc5280#page-50
            # https://source.chromium.org/chromium/chromium/src/+/main:net/cert/internal/cert_issuer_source_aia.cc
            # AiaRequest::AddCompletedFetchToResults
            cert = self._load_cert_from_bytes(cert_bytes)
            self._write_cert_cache(url_parsed, cert)
            return cert

    def aia_chase(self, host, timeout=5, max_chain_depth=100):
        """
        Get the certificate chain for host,
        up to (and including) the root certificate.

        The result is a tuple of
        0 = verified_cert_chain
        1 = missing_certs: extra certs that had to be fetched to verify the chain

        The first cert in cert_chain is the host certificate,
        the next certs are the intermediary certificates,
        the last cert is the root certificate.
        """

        # TODO throw this when an intermediary cert could not be fetched
        # raise ssl.SSLCertVerificationError("unable to get local issuer certificate")

        # TODO throw a different error when the root cert is not trusted

        # note: at this point, verified_cert_chain can be not-yet fully verified.
        # it is not-yet fully verified when the last cert is not a trusted root cert.
        verified_cert_chain, rest_cert_chain = self.get_host_cert_chain(host, timeout)

        # TODO what to do with rest_cert_chain
        # avoid fetching certs if we have them already

        # debug
        def print_chain(cert_chain):
            if not cert_chain:
                print("  (empty)")
                return
            for (idx, cert) in enumerate(cert_chain):
                print(f"  {idx} subject: {cert.get_subject()}")
                print(f"    issuer: {cert.get_issuer()})")
                print(f'    fingerprint: {cert.digest("sha1")}')

        print("verified_cert_chain"); print_chain(verified_cert_chain)
        print("rest_cert_chain"); print_chain(rest_cert_chain)

        # no. when the server sends only 1 cert
        # then rest_cert_chain is empty, but the chain can be invalid
        #if not rest_cert_chain:
        #    # full chain is valid, no missing certs were fetched
        #    return verified_cert_chain, None

        # the first cert (leaf cert) is always in verified_cert_chain
        if not verified_cert_chain:
            # no certs were received
            # TODO throw error?
            # assuming the user wants to establish a TLS connection
            # but the server did return no certificates
            return None, None

        # chase: fetch missing certs

        """
        https://groups.google.com/a/chromium.org/g/net-dev/c/H-ysp5UM_rk
        if the result returned by VerifyX509CertChain() is CERT_VERIFY_STATUS_ANDROID_NO_TRUSTED_ROOT,
        then we check if an AIA extension is present in the last certificate in the provided chain.
        If so, enter the following loop:
        - Create a new AIARequest and call Start() and then Wait() on it.
        - If the result of the request is an error,
          then return the previous error from the last call to VerifyX509CertChain().
        - Parse the result as an X509Certificate.
          If it successfully parses, then construct a new certificate with the previous certificate chain
          with the newly fetched intermediate appended and call VerifyX509CertChain() on it.
        - If the result is still CERT_VERIFY_STATUS_ANDROID_NO_TRUSTED_ROOT,
          then loop, up to a maximum number of intermediate fetches.
        """

        #store = OpenSSL.crypto.X509Store()
        # local cert store so we can add temporary certs
        store = self._context.get_cert_store()

        # verified_cert_chain[0:-1] certs are verified
        # verified_cert_chain[-1] cert is not verified

        cert = verified_cert_chain[-1] # not verified

        missing_certs = []

        for verify_chain_idx in range(max_chain_depth):

            print("cert subject", cert.get_subject())
            print("cert issuer ", cert.get_issuer())

            aia_ca_issuers = get_ca_issuers_of_cert(cert)
            print("aia_ca_issuers", aia_ca_issuers)
            if len(aia_ca_issuers) == 0:
                raise Exception("unable to get local issuer certificate. cert has no aia_ca_issuers")
            assert len(aia_ca_issuers) > 0
            #assert len(aia_ca_issuers) == 1 # ?
            issuer_cert = self._get_ca_issuer_cert(aia_ca_issuers[0])
            print("issuer_cert subject", issuer_cert.get_subject())
            print("issuer_cert issuer ", issuer_cert.get_issuer())
            missing_certs.append(issuer_cert)
            #missing_certs = [issuer_cert]

            print("missing_certs"); print_chain(missing_certs)

            # verify this cert
            #while True:
            #for i in range(2):
            #print("verify try", i)
            # https://github.com/pyca/pyopenssl/pull/948
            ctx = OpenSSL.crypto.X509StoreContext(store, cert, missing_certs)
            #ctx = OpenSSL.crypto.X509StoreContext(store, cert, [issuer_cert])
            try:
                ctx.verify_certificate()
                print("cert is valid. full chain is valid, no missing certs were fetched")
                # cert is valid
                # full chain is valid, no missing certs were fetched
                #verified_cert_chain.append(issuer_cert.to_cryptography())
                verified_cert_chain.append(issuer_cert)
                verified_cert_chain = list(map(lambda c: c.to_cryptography(), verified_cert_chain))
                return verified_cert_chain, missing_certs
            except OpenSSL.crypto.X509StoreContextError as exc:
                if exc.errors[0] == 20:
                    # exc.errors [20, 1, 'unable to get local issuer certificate']
                    print("chain is not complete -> continuing chase")
                    #import time; time.sleep(5)
                    cert = issuer_cert
                    continue
                if exc.errors[0] == 19:
                    # exc.errors [19, 1, 'self-signed certificate in certificate chain']
                    print("chain ends with untrusted root cert")
                    raise
                print("exc.args", exc.args)
                print("exc.certificate", exc.certificate)
                print("exc.errors", exc.errors)
                print("exc str", str(exc))
                raise

        # on success, we return from the previous for loop
        # TODO use a more specific exception
        raise Exception("exceeded max_chain_depth")

        ###############

        '''

        print("mmkay")

        raise 123

        # get_peer_cert_chain
        # get_verified_chain
        # add_extra_chain_cert(certobj)

        # TODO validate chain, step by step

        der_cert = cert_chain[0]
        der_cert_was_fetched = False

        # Traverse the AIA path until it gets a self-signed certificate
        # or a certificate without a "parent" issuer URI reference
        while True:
            cert_dict = openssl_get_cert_info(der_cert)
            cert_issuer = cert_dict["issuer"]
            print("cert_issuer", cert_issuer, cert_issuer in self._trusted)
            if cert_dict["subject"] == cert_issuer:  # Self-signed (root) cert # is this enough?
                if cert_issuer not in self._trusted:
                    raise InvalidCAError("Root in AIA but not in trusted list")
                # is this enough?
                logger.debug(f"Found a self-signed (root) certificate for "
                             f"{host} in AIA, and it's also in trusted list!")
                yield (self._trusted[cert_issuer], False)
                return
            yield (der_cert, der_cert_was_fetched)

            if cert_issuer in self._trusted:
                # is this enough?
                yield (self._trusted[cert_issuer], False)
                return

            if not cert_dict["aia_ca_issuers"]: # FIXME wrong condition?
                if cert_issuer not in self._trusted:
                    raise InvalidCAError("Root not in trusted database")
                logger.debug(f"Found the {host} certificate root!")
                yield (self._trusted[cert_issuer], False)
                return
            logger.debug(f"Found another {host} certificate chain entry (AIA)")
            print(f"Found another {host} certificate chain entry (AIA)")
            der_cert = self._get_ca_issuer_cert(cert_dict["aia_ca_issuers"][0])
            der_cert_was_fetched = True
        '''

    def validate_certificate_chain(self, certs):
        """
        Validate a given certificate chain which should be full,
        as a list of DER (binary) certificates from leaf to root
        (in this order and including both),
        raising an ``ssl.SSLError`` when the chain isn't valid.
        """
        target_cert = certs[0]
        intermediary_cert_list = certs[1:-1]
        root_cert = certs[-1]

        # https://cryptography.io/en/latest/x509/verification/

        """
        # prefer os.environ.get("SSL_CERT_FILE")
        # or "SYSTEM_CERTIFICATE_PATH"
        # /nix/store/ad8lpasryg34dv93h3n359bri176pj56-nss-cacert-3.98/etc/ssl/certs/ca-bundle.crt

        #print("certifi.where()", certifi.where())
        # /nix/store/ad8lpasryg34dv93h3n359bri176pj56-nss-cacert-3.98/etc/ssl/certs/ca-bundle.crt

        ca_bundle_path = (
            os.environ.get("SSL_CERT_FILE") or
            os.environ.get("SYSTEM_CERTIFICATE_PATH") or
            certifi.where()
        )
        """

        ca_bundle_path = certifi.where()

        with open(ca_bundle_path, "rb") as pems:
            store = x509.verification.Store(x509.load_pem_x509_certificates(pems.read()))

        builder = x509.verification.PolicyBuilder().store(store)

        target_name = get_cn_of_name(target_cert.subject) # can be "*.example.com"
        target_name = target_name.replace("*", "x") # fix: ValueError: invalid domain name
        target_subject = x509.DNSName(target_name)

        verifier = builder.build_server_verifier(target_subject)

        try:
            verifier.verify(target_cert, intermediary_cert_list)
        except x509.verification.VerificationError:
            raise ssl.SSLError
        # this should be unreachable since target_name.replace
        #except x509.UnsupportedGeneralNameType:
        #    raise ssl.SSLError

    def cadata_from_host(self, host, **kwargs):
        """
        Get the certification chain, apart from the leaf node,
        as joined PEM (ASCII string in base64 with extra delimiters)
        certificates in a single string, to be used in a SSLContext.
        """
        cadata, host_regex = self.cadata_and_host_regex_from_host(host, **kwargs)
        return cadata

    def cadata_and_host_regex_from_host(self, host, only_missing=False, timeout=5):
        """
        Get the certification chain and the host regex.
        Note: The host regex only matches lowercase hostnames.
        The host regex also matches ports like example.com:12345.
        Set only_missing to True to get only the missing certificates.
        See also cadata_from_host
        """
        host = host.lower()

        print("cadata_and_host_regex_from_host", host)

        for host_regex in self._cadata_from_host_regex:
            print("host_regex", host_regex)
            if host_regex.fullmatch(host):
                print("cadata_and_host_regex_from_host read cache")
                # read cache
                cadata = self._cadata_from_host_regex[host_regex]
                return cadata, host_regex

        print("cadata_and_host_regex_from_host cache miss")

        # note: this can throw
        cert_chain, missing_certs = self.aia_chase(host, timeout)

        target_cert = cert_chain[0]
        #target_cert = target_cert.to_cryptography()
        #print("target_cert", repr(target_cert), dir(target_cert), target_cert.public_bytes(cryptography.hazmat.primitives.serialization.Encoding.PEM))

        cadata = "\n".join(map(lambda c: c.public_bytes(Encoding.PEM).decode("ascii"), cert_chain))

        '''
        target_name = get_cn_of_name(target_cert.subject).lower() # can be "*.example.com"
        #target_name = target_cert.get_subject()
        print("target_name", repr(target_name))

        # host can have port. target_name has no port
        # port is between 0 and 65535 inclusive
        host_regex = target_name.replace(".", "\\.").replace("*", ".*") + "(?::[0-9]{1,5})?"
        host_regex = re.compile(host_regex)

        #print("cert_chain", cert_chain)

        #der_cert_tuples = list(self.aia_chase(host))
        '''

        '''
        der_certs = [t[0] for t in der_cert_tuples]

        der_cert_was_fetched_list = [t[1] for t in der_cert_tuples]
        print("der_cert_was_fetched_list", der_cert_was_fetched_list)

        # TODO move up to aia_chase
        #   load cert as soon as possible to avoid double-parsing
        certs = list(map(x509.load_der_x509_certificate, der_certs))

        logger.info(f"Checking the {host} certificate chain...")
        self.validate_certificate_chain(certs)
        logger.info(f"The {host} certificate chain is valid!")

        if only_missing:
            cadata = "".join(ssl.DER_cert_to_PEM_cert(t[0]) for t in der_cert_tuples[1:] if t[1])
        else:
            cadata = "".join(ssl.DER_cert_to_PEM_cert(dc) for dc in der_certs[1:])

        target_cert = certs[0]
        '''

        target_name = get_cn_of_name(target_cert.subject).lower() # can be "*.example.com"

        # host can have port. target_name has no port
        # port is between 0 and 65535 inclusive
        host_regex = target_name.replace(".", "\\.").replace("*", ".*") + "(?::[0-9]{1,5})?"
        host_regex = re.compile(host_regex)

        # limit cache size
        # fifo cache. simpler than lru cache
        while len(self._cadata_from_host_regex) > 128:
            key = next(iter(self._cadata_from_host_regex))
            del self._cadata_from_host_regex[key]

        # write cache
        self._cadata_from_host_regex[host_regex] = cadata

        return cadata, host_regex

    def cadata_from_url(self, url, **kwargs):
        """Façade to the ``cadata_from_host`` method."""
        split_result = urlsplit(url)
        return self.cadata_from_host(split_result.netloc, **kwargs)

    def ssl_context_from_host(self, host, purpose=ssl.Purpose.SERVER_AUTH, **kwargs):
        """
        SSLContext instance for a single host name
        that gets (and validates) its certificate chain from AIA.
        """
        return ssl.create_default_context(
            purpose=purpose,
            cadata=self.cadata_from_host(host, **kwargs),
        )

    def ssl_context_from_url(self, url, purpose=ssl.Purpose.SERVER_AUTH):
        """
        Same to the ``ssl_context_from_host`` method,
        but with the host name obtained from the given URL.
        """
        return ssl.create_default_context(
            purpose=purpose,
            cadata=self.cadata_from_url(url),
        )

    def urlopen(self, url, data=None, timeout=None):
        """Same to ``urllib.request.urlopen``, but handles AIA."""
        url_string = url.full_url if isinstance(url, Request) else url
        context = self.ssl_context_from_url(url_string)
        kwargs = {"data": data, "timeout": timeout, "context": context}
        cleaned_kwargs = {k: v for k, v in kwargs.items() if v is not None}
        return urlopen(url, **cleaned_kwargs)

    def download(self, url):
        """A simple façade to get a raw bytes download."""
        resp = self.urlopen(Request(
            url=url,
            headers={"User-Agent": self.user_agent},
        ))
        if resp.status != 200:
            raise DownloadError(f"HTTP {resp.status}")
        return resp.read()
