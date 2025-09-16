import os
from functools import lru_cache, partial
import logging
import re
import socket
import ssl
import select
import time
from urllib.request import urlopen, Request
from urllib.parse import urlsplit
import certifi

# https://cryptography.io/en/latest/x509/
import cryptography
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import AuthorityInformationAccess, Certificate, DNSName, load_pem_x509_certificate, load_pem_x509_certificates, load_der_x509_certificate
from cryptography.x509.extensions import ExtensionNotFound
cryptography.x509.load_der_x509_certificate
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError
from cryptography.x509.oid import ExtensionOID, NameOID

__version__ = "0.2.0"

# logging.getLogger('aia').setLevel(logging.DEBUG)
# import aia
logger = logging.getLogger(__name__)

logger.setLevel(logging.DEBUG)  # FIXME not working
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

class StoreEnhanced():
    def __init__(self,certs):
        self.certs = list(certs)
        self.store = Store(self.certs)

    def getcerts(self):
        return self.certs
    def addcert(self,cert):
        cert_digest = cert.fingerprint(hashes.SHA256())
        for check_cert in self.certs:
            if check_cert.fingerprint(hashes.SHA256()) == cert_digest:
                return False  # cert already was added
        self.certs.append(cert)
        self.store = Store(self.certs)
        return True 
    def removecert(self,cert):
        new_certs = [ check_cert for check_cert in self.certs if check_cert.fingerprint(hashes.SHA256()) != cert.fingerprint(hashes.SHA256()) ]
        self.store = Store(new_certs)
        return len(self.certs) != len(new_certs)  # return True if cert was removed
    def getstore(self):
        return self.store


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
    for attr in name:
        if attr.rfc4514_attribute_name == "CN":
            return attr.value


def get_ca_issuers_of_cert(cert):
    # convert cert from pyopenssl to cryptography
    try:
        aia_extension = cert.extensions.get_extension_for_class(
            AuthorityInformationAccess
        )
    except ExtensionNotFound:
        return []
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
    cert = load_der_x509_certificate(cert_der)
    cert_info = dict(
        issuer=get_cn_of_name(cert.issuer),
        subject=get_cn_of_name(cert.subject),
        aia_ca_issuers=get_ca_issuers_of_cert(cert),
    )
    return cert_info


def print_cert(cert, label=None, indent=""):
    if label:
        print(indent + label + ":")
    if isinstance(cert, Certificate):
        # cryptography cert
        # https://cryptography.io/en/latest/x509/reference/
        print(indent + f"  subject: {cert.subject}")
        print(indent + f"    issuer: {cert.issuer})")
        print(indent + f"    fingerprint: {cert.fingerprint(hashes.SHA256())}")
        return
    raise ValueError("unknown cert type {type(cert)}")


def print_chain(cert_chain, label=None):
    if label:
        print(label + ":")
    if not cert_chain:
        print("  (empty)")
        return
    for idx, cert in enumerate(cert_chain):
        print_cert(cert, f"cert {idx}", "  ")


class AIASession:

    def __init__(
        self,
        url,
        user_agent=DEFAULT_USER_AGENT,
        cafile=None,
        cache_db=None,
        cache_dir=None,
        verify_depth=None,  # default is -1 = infinite
        # TODO load/store trusted root certs
        # trusted_db=None,
        # trusted_dir=None,
    ):
        """
        Create a new session.
        Downloaded certificates are cached in cache_dir or cache_db.
        """
        logger.debug("creating AIASession")
        self.user_agent = user_agent
        self.cafile = cafile
        if not cafile:
            import certifi

            self.cafile = certifi.where()
        self.cache_db = cache_db
        self.cache_db_con = None
        self.cache_db_cur = None
        self.verify_depth = verify_depth
        self.cache_dir = cache_dir
        self._ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self._ssl_context.verify_mode = ssl.CERT_OPTIONAL
        # this throws OpenSSL.SSL.Error if cafile is missing or empty
        self._ssl_context.load_verify_locations(cafile=self.cafile)
        self._cadata_from_host_regex = dict()
        self._trusted_root_certs = list()
        self.base_url = urlsplit(url).netloc

        with open(certifi.where(), "rb") as pems:
            self.local_store = StoreEnhanced(load_pem_x509_certificates(pems.read()))

    @CachedMethod
    def get_host_cert_chain(self, host, timeout=5):
        logger.debug(f"Downloading TLS certificate chain from https://{host}")
        port = 443
        if ":" in host:
            host, port = host.split(":")
            port = int(port)
        # https://stackoverflow.com/a/67212703/10440128
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn = self._ssl_context.wrap_socket(
            sock,
            server_hostname=host
        )
        conn.settimeout(timeout)
        # NOTE this block can throw OpenSSL.SSL.Error ...
        cert_pem = ssl.get_server_certificate((host, port))  # Retrieve SSL server certificate
        return cert_pem
		
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
        query = "\n".join(
            [
                "CREATE TABLE certs (",
                "  url TEXT PRIMARY KEY,",
                "  cert_der BLOB",
                ")",
            ]
        )
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
                cert = load_der_x509_certificate(cert_der)
                return cert
        if self.cache_dir:
            cache_path = self.cache_dir + "/" + url_parsed.netloc + "/certificate.der"
            if os.path.exists(cache_path):
                logger.debug(f"found cert in cache_dir: {url}")
                with open(cache_path, "rb") as f:
                    cert_der = f.read()
                cert = load_der_x509_certificate(cert_der)
                return cert
        logger.debug(f"not found cert in cache: {url}")

    def _write_cert_cache(self, url_parsed, cert):
        if not self.cache_dir and not self.cache_db:
            # caching is disabled
            return
        url = url_parsed.geturl()
        if self.cache_db:
            logger.debug(f"adding cert to cache_db: {url}")
            self._init_cache_db()
            query = "insert into certs (url, cert_der) values (?, ?)"
            args = (url, cert.public_bytes(Encoding.DER))
            cur = self.cache_db_cur.execute(query, args)
            if cur.rowcount != 1:
                logger.warning(f"failed to add cert to cache_db: {url}")
            # write to disk
            self.cache_db_con.commit()
        if self.cache_dir:
            cache_path = self.cache_dir + "/" + url_parsed.netloc + "/certificate.der"
            # check again if cache_path exists. can have multiple writers
            if not os.path.exists(cache_path):
                logger.debug(f"adding cert to cache_dir: {url}")
                os.makedirs(os.path.dirname(cache_path), exist_ok=True)
                with open(cache_path, "wb") as f:
                    f.write(cert.public_bytes(Encoding.DER))

    def _load_cert_from_bytes(self, cert_bytes):
        # try to load DER = ASN1 format

        try:
            cert = load_der_x509_certificate(cert_bytes)
            return cert
        except ValueError:
            pass
        # except Exception as exc:
        #    print("exc", type(exc), exc)
        #    raise

        # try to load PKCS7 format
        # https://chromium.googlesource.com/chromium/src/+/refs/heads/main/net/cert/internal/cert_issuer_source_aia.cc
        # https://cryptography.io/ # pkcs7
        # ParseCertsFromCms

        # try to load PKCS7-DER format
        try:
            certs = pkcs7.load_der_pkcs7_certificates(cert_bytes)
            assert len(certs) == 1  # TODO
            cert = certs[0]
            return cert
        except ValueError:
            # ValueError: Unable to parse PKCS7 data
            pass
        # except Exception as exc:
        #    print("exc", type(exc), exc)
        #    raise

        # try to load PKCS7-PEM format
        try:
            certs = pkcs7.load_pem_pkcs7_certificates(cert_bytes)
            assert len(certs) == 1  # TODO
            cert = certs[0]
            return cert
        except ValueError:
            # ValueError: Unable to parse PKCS7 data
            pass
        # except Exception as exc:
        #    print("exc", type(exc), exc)
        #    raise

        # try to load PEM format
        try:
            cert = load_pem_x509_certificate(cert_bytes)
            return cert
        except ValueError:
            pass
        # try:
        # except Exception as exc:
        #    print("exc", type(exc), exc)
        #    raise

        # TODO more specific
        raise Exception(
            f"failed to parse cert from cert_bytes {cert_bytes.hex()}"
        )

    @CachedMethod
    def _get_ca_issuer_cert(self, url, timeout=5):
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
        # TODO async? asyncio + aiohttp
        with urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                raise AIADownloadError(f"HTTP {resp.status} (CA Issuer Cert.)")
            cert_bytes = resp.read()
            # cert_bytes can have different formats: DER = ASN1, CMS = PKCS7 = P7B, PEM
            # https://tools.ietf.org/html/rfc5280#page-50
            # https://chromium.googlesource.com/chromium/src/+/refs/heads/main/net/cert/internal/cert_issuer_source_aia.cc
            # AiaRequest::AddCompletedFetchToResults
            cert = self._load_cert_from_bytes(cert_bytes)
            self._write_cert_cache(url_parsed, cert)
            return cert


    def add_trusted_root_cert_file(self, cert_file):
        with open(cert_file, "rb") as f:
            cert_bytes = f.read()
        cert = self._load_cert_from_bytes(cert_bytes)
        return self.add_trusted_root_cert(cert)

    def add_trusted_root_cert(self, cert):
        assert isinstance(cert, Certificate)
        try:
            ext_bc=cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        except ExtensionNotFound:
            raise ValueError("must be a CA cert")
        if not ext_bc.value.ca:
            raise ValueError("must be a CA cert")
        if cert.issuer != cert.subject:
            raise ValueError("must be a self-signed cert")
        if (self.local_store.addcert(cert)):
            digest_hex = cert.fingerprint(hashes.SHA256())
            logger.debug(f"adding trusted root cert {digest_hex}")
            return True  # cert was added
        return False

    def remove_trusted_root_cert_file(self, cert_file):
        with open(cert_file, "rb") as f:
            cert_bytes = f.read()
        cert = self._load_cert_from_bytes(cert_bytes)
        return self.remove_trusted_root_cert(cert)

    def remove_trusted_root_cert(self, cert):
        assert isinstance(cert, Certificate)
        return self.local_store.removecert(cert) # return True if cert was removed

    def aia_chase(self, host, timeout=5):
        """
        Get the certificate chain for host,
        up to (and including) the root certificate.

        The result is a tuple of
        0 = verified_cert_chain
        1 = missing_certs

        The first cert in verified_cert_chain is the host certificate,
        the next certs are the intermediary certificates,
        the last cert is the root certificate.

        missing_certs are the extra certs
        that had to be fetched to verify the chain.
        """

        # TODO throw this when an intermediary cert could not be fetched
        # raise ssl.SSLCertVerificationError("unable to get local issuer certificate")

        host_cert_chain = self.get_host_cert_chain(host, timeout)

        # print_chain(host_cert_chain, "host_cert_chain")

        # the first cert (leaf cert) is always in host_cert_chain
        if not host_cert_chain:
            # no certs were received
            # TODO throw error?
            # assuming the user wants to establish a SSL connection
            # but the server did return no certificates
            return None, None

        missing_certs = []
        leaf_cert = load_pem_x509_certificate(str.encode(host_cert_chain))

        self.builder = PolicyBuilder().store(self.local_store.getstore())
        self._verifier = self.builder.build_server_verifier(DNSName(self.base_url))

        if self.verify_depth is not None:
            verify_depth = self.verify_depth
        else:
            verify_depth = self._verifier.max_chain_depth
        for _verify_chain_idx in range(verify_depth):
            try:
                verified_chain = self._verifier.verify(leaf_cert, missing_certs)
                return verified_chain, missing_certs
            except VerificationError as e:
                logger.debug(
                    f"fetching missing issuer cert for cert {leaf_cert.subject}"
                )

                aia_ca_issuers = get_ca_issuers_of_cert(leaf_cert)
                logger.debug("aia_ca_issuers", aia_ca_issuers)
                if len(aia_ca_issuers) == 0:
                    raise Exception(
                        "unable to get local issuer certificate. "
                        "cert has no aia_ca_issuers"
                    )
                issuer_cert = self._get_ca_issuer_cert(aia_ca_issuers[0], timeout)
                logger.debug("issuer_cert subject", issuer_cert.subject)
                # logger.debug("issuer_cert issuer ", issuer_cert.get_issuer())
                missing_certs.append(issuer_cert)
                # print_chain(missing_certs, "missing_certs")
                continue

        # on success, we return from the previous for loop
        # TODO use a more specific exception
        raise Exception("exceeded verify_depth")

    def cadata_from_host(self, host, **kwargs):
        """
        Get the certification chain, apart from the leaf node,
        as joined PEM (ASCII string in base64 with extra delimiters)
        certificates in a single string, to be used in a SSLContext.
        """
        cadata, _host_regex = self.cadata_and_host_regex_from_host(host, **kwargs)
        return cadata

    # TODO remove?
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
        cert_chain, _missing_certs = self.aia_chase(host, timeout)

        target_cert = cert_chain[0]
        target_name = target_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

        # host can have port. target_name has no port
        # port is between 0 and 65535 inclusive
        host_regex = (
            target_name.replace(".", "\\.").replace("*", ".*") + "(?::[0-9]{1,5})?"
        )
        host_regex = re.compile(host_regex)

        # limit cache size
        # fifo cache. simpler than lru cache
        while len(self._cadata_from_host_regex) > 128:
            key = next(iter(self._cadata_from_host_regex))
            del self._cadata_from_host_regex[key]

        # write cache
        self._cadata_from_host_regex[host_regex] = b"" 
        for cert in cert_chain:
            self._cadata_from_host_regex[host_regex] += cert.public_bytes(encoding=Encoding.PEM)


        return self._cadata_from_host_regex[host_regex], host_regex

    def cadata_from_url(self, url, **kwargs):
        """Façade to the ``cadata_from_host`` method."""
        url_parsed = urlsplit(url)
        return self.cadata_from_host(url_parsed.netloc, **kwargs)

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
        # TODO? Audit url open for permitted schemes.
        # Allowing use of file:/ or custom schemes is often unexpected.
        context = self.ssl_context_from_url(url_string)
        kwargs = {"data": data, "timeout": timeout, "context": context}
        cleaned_kwargs = {k: v for k, v in kwargs.items() if v is not None}
        return urlopen(url, **cleaned_kwargs)

    def download(self, url):
        """A simple façade to get a raw bytes download."""
        resp = self.urlopen(
            Request(
                url=url,
                headers={"User-Agent": self.user_agent},
            )
        )
        if resp.status != 200:
            raise DownloadError(f"HTTP {resp.status}")
        return resp.read()
