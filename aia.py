import os
from contextlib import ExitStack
from functools import lru_cache, partial
import logging
import re
import socket
import ssl
from tempfile import NamedTemporaryFile
from urllib.request import urlopen, Request
from urllib.parse import urlsplit

# https://cryptography.io/en/latest/x509/
from cryptography import x509

import certifi


__version__ = "0.2.0"

logger = logging.getLogger(__name__)

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
            cache_dir=None,
        ):
        """
        Create a new session.
        cache_dir is a directory path,
        where downloaded intermediary certificates are stored.
        """
        self.user_agent = user_agent
        self.cache_dir = cache_dir
        self._context = ssl.SSLContext()  # TLS (don't check broken chain)
        self._context.load_default_certs()

        # Trusted certificates whitelist in dict format like:
        # {"RFC4514 string": b"DER certificate contents"}
        self._trusted = {
            openssl_get_cert_info(ca_der)["subject"]: ca_der
            for ca_der in self._context.get_ca_certs(True)
        }

        self._cadata_from_host_regex = dict()

    @CachedMethod
    def get_host_cert(self, host):
        """
        Get the DER (binary) certificate for the target host
        without checking it (leaf certificate).
        """
        logger.debug(f"Downloading {host} certificate (TLS)")
        port = 443
        if ':' in host:
            host, port = host.split(':')
        with socket.create_connection((host, port)) as sock:
            with self._context.wrap_socket(sock, server_hostname=host) as ss:
                return ss.getpeercert(True)

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
            raise AIASchemeError("Invalid CA issuer certificate URI protocol")
        if self.cache_dir:
            cache_path = self.cache_dir + "/" + url_parsed.netloc + url_parsed.path
        else:
            cache_path = None
        if cache_path and os.path.exists(cache_path):
            with open(cache_path, "rb") as f:
                return f.read() # read cache
        logger.debug(f"Downloading CA issuer certificate at {url}")
        req = Request(url=url, headers={"User-Agent": self.user_agent})
        with urlopen(req) as resp:
            if resp.status != 200:
                raise AIADownloadError(f"HTTP {resp.status} (CA Issuer Cert.)")
            data = resp.read()
            # check again if cache_path exists. can have multiple writers
            if cache_path and not os.path.exists(cache_path):
                os.makedirs(os.path.dirname(cache_path), exist_ok=True)
                with open(cache_path, "wb") as f:
                    f.write(data) # write cache
            return data

    def aia_chase(self, host):
        """
        Generator of the certificate chain from a host,
        up to (and including) the root certificate.

        The result is a list a DER bytestring certificate,
        whose first item is the host certificate and the next entries
        are the intermediary certificates.
        """
        der_cert = self.get_host_cert(host)

        # Traverse the AIA path until it gets a self-signed certificate
        # or a certificate without a "parent" issuer URI reference
        while True:
            cert_dict = openssl_get_cert_info(der_cert)
            cert_issuer = cert_dict["issuer"]
            if cert_dict["subject"] == cert_issuer:  # Self-signed (root) cert
                if cert_issuer not in self._trusted:
                    raise InvalidCAError("Root in AIA but not in trusted list")
                logger.debug(f"Found a self-signed (root) certificate for "
                             f"{host} in AIA, and it's also in trusted list!")
                yield self._trusted[cert_issuer]
                return
            yield der_cert
            if not cert_dict["aia_ca_issuers"]:
                if cert_issuer not in self._trusted:
                    raise InvalidCAError("Root not in trusted database")
                logger.debug(f"Found the {host} certificate root!")
                yield self._trusted[cert_issuer]
                return
            logger.debug(f"Found another {host} certificate chain entry (AIA)")
            der_cert = self._get_ca_issuer_cert(cert_dict["aia_ca_issuers"][0])

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

        with open(certifi.where(), "rb") as pems:
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

    def cadata_from_host(self, host):
        """
        Get the certification chain, apart from the leaf node,
        as joined PEM (ASCII string in base64 with extra delimiters)
        certificates in a single string, to be used in a SSLContext.
        """
        cadata, host_regex = self.cadata_and_host_regex_from_host(host)
        return cadata

    def cadata_and_host_regex_from_host(self, host):
        """
        Get the certification chain and the host regex.
        Note: The host regex only matches lowercase hostnames.
        The host regex also matches ports like example.com:12345.
        See also cadata_from_host
        """
        host = host.lower()

        for host_regex in self._cadata_from_host_regex:
            if host_regex.fullmatch(host):
                # read cache
                cadata = self._cadata_from_host_regex[host_regex]
                return cadata, host_regex

        der_certs = list(self.aia_chase(host))

        # TODO move up to aia_chase
        #   load cert as soon as possible to avoid double-parsing
        certs = list(map(x509.load_der_x509_certificate, der_certs))

        logger.info(f"Checking the {host} certificate chain...")
        self.validate_certificate_chain(certs)
        logger.info(f"The {host} certificate chain is valid!")
        cadata = "".join(ssl.DER_cert_to_PEM_cert(dc) for dc in der_certs[1:])

        target_cert = certs[0]
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

    def cadata_from_url(self, url):
        """Façade to the ``cadata_from_host`` method."""
        split_result = urlsplit(url)
        return self.cadata_from_host(split_result.netloc)

    def ssl_context_from_host(self, host, purpose=ssl.Purpose.SERVER_AUTH):
        """
        SSLContext instance for a single host name
        that gets (and validates) its certificate chain from AIA.
        """
        return ssl.create_default_context(
            purpose=purpose,
            cadata=self.cadata_from_host(host),
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
