"""
aether_protocol_c/timestamp_authority.py

RFC 3161 Trusted Timestamp Authority integration.

Provides third-party timestamping of commitment data via RFC 3161-compliant
Timestamp Authorities (TSAs).  A timestamp token proves that the data existed
at a specific point in time, as certified by an independent authority.

The module uses only stdlib ``urllib.request`` for HTTP and ``pyasn1`` for
ASN.1 DER encoding/decoding of TimeStampReq / TimeStampResp messages.

Usage::

    from aether_protocol_c.timestamp_authority import RFC3161TimestampAuthority

    tsa = RFC3161TimestampAuthority()
    token = tsa.stamp(commitment_bytes)
    assert tsa.verify(commitment_bytes, token)
"""

from __future__ import annotations

import hashlib
import logging
import os
import ssl
import time
import urllib.error
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

try:
    from pyasn1.type import univ, namedtype, tag, useful, constraint
    from pyasn1.codec.der import encoder as der_encoder
    from pyasn1.codec.der import decoder as der_decoder
    _PYASN1_AVAILABLE = True
except ImportError:
    _PYASN1_AVAILABLE = False

try:
    from pyasn1_modules import rfc3161, rfc5652
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    _CMS_VERIFY_AVAILABLE = True
except ImportError:
    _CMS_VERIFY_AVAILABLE = False

# OIDs for digest algorithms that may appear in a TSA's CMS SignerInfo.
_DIGEST_OID_TO_HASH_ALGO = {
    "1.3.14.3.2.26": "sha1",
    "2.16.840.1.101.3.4.2.1": "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
}


# ── ASN.1 structures for RFC 3161 ────────────────────────────────────

if _PYASN1_AVAILABLE:

    class MessageImprint(univ.Sequence):
        """ASN.1 MessageImprint ::= SEQUENCE { hashAlgorithm, hashedMessage }"""
        componentType = namedtype.NamedTypes(
            namedtype.NamedType(
                "hashAlgorithm",
                univ.Sequence(
                    componentType=namedtype.NamedTypes(
                        namedtype.NamedType("algorithm", univ.ObjectIdentifier()),
                        namedtype.OptionalNamedType("parameters", univ.Any()),
                    )
                ),
            ),
            namedtype.NamedType(
                "hashedMessage", univ.OctetString()
            ),
        )

    class TimeStampReq(univ.Sequence):
        """ASN.1 TimeStampReq per RFC 3161."""
        componentType = namedtype.NamedTypes(
            namedtype.NamedType("version", univ.Integer()),
            namedtype.NamedType("messageImprint", MessageImprint()),
            namedtype.OptionalNamedType("reqPolicy", univ.ObjectIdentifier()),
            namedtype.OptionalNamedType("nonce", univ.Integer()),
            namedtype.DefaultedNamedType(
                "certReq",
                univ.Boolean(False).subtype(
                    implicitTag=tag.Tag(
                        tag.tagClassContext, tag.tagFormatSimple, 0
                    )
                ),
            ),
        )

    # OID for SHA-256
    _SHA256_OID = univ.ObjectIdentifier((2, 16, 840, 1, 101, 3, 4, 2, 1))

    class PKIStatusInfo(univ.Sequence):
        """ASN.1 PKIStatusInfo ::= SEQUENCE { status, statusString OPTIONAL, failInfo OPTIONAL }"""
        componentType = namedtype.NamedTypes(
            namedtype.NamedType("status", univ.Integer()),
            namedtype.OptionalNamedType(
                "statusString", univ.SequenceOf(componentType=univ.Any())
            ),
            namedtype.OptionalNamedType("failInfo", univ.BitString()),
        )

    class ContentInfo(univ.Sequence):
        """ASN.1 ContentInfo ::= SEQUENCE { contentType, content [0] EXPLICIT ANY }"""
        componentType = namedtype.NamedTypes(
            namedtype.NamedType("contentType", univ.ObjectIdentifier()),
            namedtype.OptionalNamedType(
                "content",
                univ.Any().subtype(
                    explicitTag=tag.Tag(
                        tag.tagClassContext, tag.tagFormatConstructed, 0
                    )
                ),
            ),
        )

    class TimeStampResp(univ.Sequence):
        """ASN.1 TimeStampResp ::= SEQUENCE { status, timeStampToken OPTIONAL }"""
        componentType = namedtype.NamedTypes(
            namedtype.NamedType("status", PKIStatusInfo()),
            namedtype.OptionalNamedType("timeStampToken", ContentInfo()),
        )

    class AlgorithmIdentifier(univ.Sequence):
        """ASN.1 AlgorithmIdentifier ::= SEQUENCE { algorithm, parameters OPTIONAL }"""
        componentType = namedtype.NamedTypes(
            namedtype.NamedType("algorithm", univ.ObjectIdentifier()),
            namedtype.OptionalNamedType("parameters", univ.Any()),
        )

    class EncapsulatedContentInfo(univ.Sequence):
        """ASN.1 EncapsulatedContentInfo ::= SEQUENCE { eContentType, eContent [0] EXPLICIT OCTET STRING OPTIONAL }"""
        componentType = namedtype.NamedTypes(
            namedtype.NamedType("eContentType", univ.ObjectIdentifier()),
            namedtype.OptionalNamedType(
                "eContent",
                univ.OctetString().subtype(
                    explicitTag=tag.Tag(
                        tag.tagClassContext, tag.tagFormatSimple, 0
                    )
                ),
            ),
        )

    class SignedData(univ.Sequence):
        """ASN.1 SignedData (CMS) ::= SEQUENCE { version, digestAlgorithms, encapContentInfo, certificates OPTIONAL, crls OPTIONAL, signerInfos }"""
        componentType = namedtype.NamedTypes(
            namedtype.NamedType("version", univ.Integer()),
            namedtype.NamedType(
                "digestAlgorithms", univ.SetOf(componentType=AlgorithmIdentifier())
            ),
            namedtype.NamedType("encapContentInfo", EncapsulatedContentInfo()),
            namedtype.OptionalNamedType(
                "certificates",
                univ.Any().subtype(
                    implicitTag=tag.Tag(
                        tag.tagClassContext, tag.tagFormatConstructed, 0
                    )
                ),
            ),
            # Note: CMS SignedData also permits an OPTIONAL [1] IMPLICIT
            # `crls` field between `certificates` and `signerInfos`. It is
            # intentionally not modeled here (pyasn1's schema-mode decoder
            # cannot cleanly disambiguate two adjacent optional
            # implicit-tagged ANY fields). RFC 3161 TSA responses do not
            # populate this field in practice; a response that did would
            # fail parsing here and verify() would conservatively return
            # False (fail-closed), never a false positive.
            namedtype.NamedType("signerInfos", univ.SetOf(componentType=univ.Any())),
        )

    class TSTInfo(univ.Sequence):
        """ASN.1 TSTInfo ::= SEQUENCE { version, policy, messageImprint, serialNumber, genTime, ... }"""
        componentType = namedtype.NamedTypes(
            namedtype.NamedType("version", univ.Integer()),
            namedtype.NamedType("policy", univ.ObjectIdentifier()),
            namedtype.NamedType("messageImprint", MessageImprint()),
            namedtype.NamedType("serialNumber", univ.Integer()),
            namedtype.NamedType("genTime", useful.GeneralizedTime()),
            namedtype.OptionalNamedType("accuracy", univ.Any()),
            namedtype.DefaultedNamedType("ordering", univ.Boolean(False)),
            namedtype.OptionalNamedType("nonce", univ.Integer()),
            namedtype.OptionalNamedType(
                "tsa",
                univ.Any().subtype(
                    implicitTag=tag.Tag(
                        tag.tagClassContext, tag.tagFormatConstructed, 0
                    )
                ),
            ),
            namedtype.OptionalNamedType(
                "extensions",
                univ.Any().subtype(
                    implicitTag=tag.Tag(
                        tag.tagClassContext, tag.tagFormatConstructed, 1
                    )
                ),
            ),
        )


# ── Data classes ──────────────────────────────────────────────────────

@dataclass(frozen=True)
class TimestampToken:
    """
    Frozen record of an RFC 3161 timestamp token.

    Fields:
        tsa_url: The TSA endpoint that issued this token.
        token_bytes: Raw DER-encoded TimeStampResp bytes.
        token_hex: Hex encoding of ``token_bytes``.
        stamped_at: Unix timestamp when the stamp was obtained.
        hash_algorithm: Hash algorithm used (always ``"sha-256"``).
        message_imprint: Hex digest of the stamped data.
    """

    tsa_url: str
    token_bytes: bytes
    token_hex: str
    stamped_at: int
    hash_algorithm: str
    message_imprint: str

    def to_dict(self) -> dict:
        """Serialise to a plain dict (suitable for JSON)."""
        return {
            "tsa_url": self.tsa_url,
            "token_hex": self.token_hex,
            "stamped_at": self.stamped_at,
            "hash_algorithm": self.hash_algorithm,
            "message_imprint": self.message_imprint,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "TimestampToken":
        """Reconstruct from a dict."""
        token_hex = d["token_hex"]
        return cls(
            tsa_url=d["tsa_url"],
            token_bytes=bytes.fromhex(token_hex),
            token_hex=token_hex,
            stamped_at=d["stamped_at"],
            hash_algorithm=d["hash_algorithm"],
            message_imprint=d["message_imprint"],
        )


class TimestampError(Exception):
    """Raised when timestamping operations fail."""


# Genuine RFC 3161 TimeStampResp tokens are typically a few KB. Cap the
# accepted response size generously above that to prevent a malicious or
# compromised TSA endpoint (or a MITM) from streaming an unbounded body
# and exhausting caller memory.
MAX_TSA_RESPONSE_BYTES = 1 * 1024 * 1024  # 1 MiB


# ── RFC 3161 Timestamp Authority ──────────────────────────────────────

class RFC3161TimestampAuthority:
    """
    Client for RFC 3161-compliant Timestamp Authorities.

    Sends a ``TimeStampReq`` over HTTP and parses the ``TimeStampResp``.
    Supports automatic fallback to a secondary TSA if the primary is
    unavailable.

    Args:
        tsa_url: Primary TSA endpoint URL.
        fallback_url: Fallback TSA endpoint URL.
        timeout: HTTP request timeout in seconds.
    """

    DEFAULT_TSA_URL = "https://timestamp.digicert.com"
    FALLBACK_TSA_URL = "https://timestamp.sectigo.com"

    def __init__(
        self,
        tsa_url: Optional[str] = None,
        fallback_url: Optional[str] = None,
        timeout: int = 10,
        allow_insecure_http: bool = False,
    ) -> None:
        """
        Args:
            tsa_url: Primary TSA endpoint URL. Must be ``https://`` unless
                ``allow_insecure_http`` is set.
            fallback_url: Fallback TSA endpoint URL. Same scheme rule applies.
            timeout: HTTP request timeout in seconds.
            allow_insecure_http: Explicit opt-in to permit plain ``http://``
                TSA URLs (e.g. for local testing). Defaults to False.

        Raises:
            TimestampError: If either URL fails scheme or host validation.
        """
        self._allow_insecure_http = allow_insecure_http
        self._tsa_url = self._validate_tsa_url(tsa_url or self.DEFAULT_TSA_URL)
        self._fallback_url = self._validate_tsa_url(
            fallback_url or self.FALLBACK_TSA_URL
        )
        self._timeout = timeout

    def _validate_tsa_url(self, url: str) -> str:
        """
        Validate a TSA URL's scheme and reject private/loopback/link-local
        hosts, guarding against SSRF and man-in-the-middle interception.

        Args:
            url: The TSA URL to validate.

        Returns:
            The validated URL, unchanged.

        Raises:
            TimestampError: If the URL uses a disallowed scheme, has no
                host, or targets a private/loopback/link-local address.
        """
        import ipaddress
        import socket
        from urllib.parse import urlparse

        parsed = urlparse(url)

        if parsed.scheme == "http" and not self._allow_insecure_http:
            raise TimestampError(
                f"Insecure TSA URL rejected: {url!r}. TSA endpoints must "
                "use https:// (pass allow_insecure_http=True to override "
                "for testing)."
            )
        if parsed.scheme not in ("http", "https"):
            raise TimestampError(
                f"TSA URL {url!r} must use http:// or https://."
            )
        if not parsed.hostname:
            raise TimestampError(f"TSA URL {url!r} has no host.")

        host = parsed.hostname
        try:
            addrs = {info[4][0] for info in socket.getaddrinfo(host, None)}
        except socket.gaierror:
            # Hostname doesn't resolve; try treating it as a literal IP.
            addrs = {host}

        for addr in addrs:
            try:
                ip = ipaddress.ip_address(addr)
            except ValueError:
                continue
            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_reserved
                or ip.is_multicast
                or ip.is_unspecified
            ):
                raise TimestampError(
                    f"TSA URL {url!r} resolves to a disallowed address "
                    f"({addr}); private/loopback/link-local targets are "
                    "not permitted."
                )

        return url

    def _build_timestamp_request(self, data: bytes) -> tuple[bytes, int]:
        """
        Build a DER-encoded RFC 3161 TimeStampReq for the given data.

        Args:
            data: The raw bytes to timestamp.

        Returns:
            A tuple of ``(der_encoded_request_bytes, nonce_value)``. The
            caller must retain ``nonce_value`` so the corresponding
            ``TimeStampResp`` can be checked for nonce-echo, defeating
            replay of a stale/substituted response (RFC 3161 §2.4.2).

        Raises:
            TimestampError: If pyasn1 is not available.
        """
        if not _PYASN1_AVAILABLE:
            raise TimestampError(
                "pyasn1 is required for RFC 3161 timestamps.  "
                "Install with:  pip install pyasn1"
            )

        digest = hashlib.sha256(data).digest()

        # Build MessageImprint
        imprint = MessageImprint()
        algo_seq = univ.Sequence()
        algo_seq.setComponentByPosition(0, _SHA256_OID)
        imprint.setComponentByName("hashAlgorithm", algo_seq)
        imprint.setComponentByName("hashedMessage", univ.OctetString(digest))

        # Build TimeStampReq
        req = TimeStampReq()
        req.setComponentByName("version", univ.Integer(1))
        req.setComponentByName("messageImprint", imprint)
        # Random nonce for replay protection
        nonce_val = int.from_bytes(os.urandom(8), "big")
        req.setComponentByName("nonce", univ.Integer(nonce_val))
        # certReq: BOOLEAN DEFAULT FALSE — use matching implicit tag
        cert_req = univ.Boolean(True).subtype(
            implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 0
            )
        )
        req.setComponentByName("certReq", cert_req)

        return der_encoder.encode(req), nonce_val

    def _extract_tst_info_nonce(self, resp_bytes: bytes) -> Optional[int]:
        """
        Parse a raw ``TimeStampResp`` and return the ``TSTInfo.nonce``
        value, if present.

        The embedded ``TSTInfo`` is decoded *schemaless* (without
        ``asn1Spec=TSTInfo()``) deliberately: ``TSTInfo``'s optional
        ``accuracy`` field is modelled as ``univ.Any()`` (see the class
        docstring), and pyasn1's schema-mode decoder cannot determine
        whether a following untagged optional/default field (``accuracy``,
        ``ordering``) is present when trailing bytes exist -- it raises
        rather than silently mis-parsing. A schemaless decode sidesteps
        this because each universally-tagged primitive (``INTEGER``,
        ``BOOLEAN``, ``SEQUENCE``, ...) is resolved directly from its own
        DER tag, with no ambiguity to resolve. ``nonce`` is the only
        top-level ``INTEGER``-tagged field in ``TSTInfo`` after
        ``serialNumber``/``genTime``, so it can be found unambiguously by
        tag once the mandatory prefix is skipped.

        Args:
            resp_bytes: Raw DER-encoded TimeStampResp bytes.

        Returns:
            The nonce value echoed by the TSA, or ``None`` if the
            TSTInfo has no nonce field.

        Raises:
            TimestampError: If the response cannot be parsed, does not
                report a granted status, or is missing the timestamp token.
        """
        try:
            resp, _ = der_decoder.decode(resp_bytes, asn1Spec=TimeStampResp())

            status = int(
                resp.getComponentByName("status").getComponentByName("status")
            )
            if status not in (0, 1):  # 0=granted, 1=grantedWithMods
                raise TimestampError(
                    f"TSA reported non-granted status: {status}"
                )

            content_info = resp.getComponentByName("timeStampToken")
            if content_info is None or not content_info.hasValue():
                raise TimestampError("TSA response is missing timeStampToken")

            signed_data_der = bytes(content_info.getComponentByName("content"))
            signed_data, _ = der_decoder.decode(
                signed_data_der, asn1Spec=SignedData()
            )

            econtent = signed_data.getComponentByName(
                "encapContentInfo"
            ).getComponentByName("eContent")
            if econtent is None or not econtent.hasValue():
                raise TimestampError("TSA response is missing eContent")

            # Schemaless decode -- see docstring above.
            tst_info, _ = der_decoder.decode(bytes(econtent))

            # Mandatory prefix: version, policy, messageImprint,
            # serialNumber, genTime -- always exactly 5 components.
            nonce_val: Optional[int] = None
            for i in range(5, len(tst_info)):
                component = tst_info.getComponentByPosition(i)
                if isinstance(component, univ.Integer):
                    nonce_val = int(component)
                    break
        except TimestampError:
            raise
        except Exception as exc:
            raise TimestampError(
                f"Failed to parse TSA response: {exc}"
            ) from exc

        return nonce_val

    def _verify_cms_signature(self, content_info_content: bytes) -> bool:
        """
        Verify the CMS ``SignedData`` signature covering a TSA's
        ``TimeStampToken``, proving the response was produced by whoever
        holds the private key for the embedded signer certificate --
        rather than trusting any bytes an HTTP endpoint chooses to return.

        Args:
            content_info_content: The DER bytes of the ``SignedData``
                (i.e. ``ContentInfo.content``) extracted from the TSA's
                ``TimeStampResp``.

        Returns:
            ``True`` if a signerInfo's signature verifies against the
            embedded signer certificate's public key; ``False`` on any
            parsing failure, missing signer/certificate, digest mismatch,
            or signature mismatch (fail-closed).
        """
        if not _CMS_VERIFY_AVAILABLE:
            return False

        try:
            signed_data, _ = der_decoder.decode(
                content_info_content, asn1Spec=rfc5652.SignedData()
            )

            econtent = bytes(
                signed_data["encapContentInfo"]["eContent"]
            )

            signer_infos = signed_data["signerInfos"]
            if len(signer_infos) < 1:
                return False

            # Collect embedded certificates (CertificateChoices -> Certificate).
            certs = []
            if signed_data["certificates"].isValue:
                for choice in signed_data["certificates"]:
                    if choice.getName() == "certificate":
                        cert_der = der_encoder.encode(choice["certificate"])
                        certs.append(x509.load_der_x509_certificate(cert_der))

            for signer_info in signer_infos:
                if self._verify_single_signer(signer_info, econtent, certs):
                    return True

            return False
        except Exception:
            # Any parsing/verification failure means the signature cannot
            # be trusted -- fail closed.
            return False

    def _verify_single_signer(
        self, signer_info, econtent: bytes, certs: list
    ) -> bool:
        """
        Verify one CMS ``SignerInfo`` against a candidate signer
        certificate's public key.

        Args:
            signer_info: A parsed ``rfc5652.SignerInfo``.
            econtent: The raw ``eContent`` (DER-encoded ``TSTInfo``) bytes.
            certs: Candidate signer certificates from ``SignedData``.

        Returns:
            ``True`` if the signature verifies; ``False`` otherwise.
        """
        if not certs:
            return False

        # Select the certificate identified by issuerAndSerialNumber when
        # present; otherwise fall back to the sole/first embedded cert.
        signer_cert = certs[0]
        sid = signer_info["sid"]
        if sid.getName() == "issuerAndSerialNumber":
            iasn = sid["issuerAndSerialNumber"]
            serial = int(iasn["serialNumber"])
            issuer_der = der_encoder.encode(iasn["issuer"])
            for cert in certs:
                if (
                    cert.serial_number == serial
                    and cert.issuer.public_bytes() == issuer_der
                ):
                    signer_cert = cert
                    break
            else:
                return False

        digest_oid = str(signer_info["digestAlgorithm"]["algorithm"])
        hash_name = _DIGEST_OID_TO_HASH_ALGO.get(digest_oid)
        if hash_name is None:
            return False
        hash_cls = {
            "sha1": hashes.SHA1,
            "sha256": hashes.SHA256,
            "sha384": hashes.SHA384,
            "sha512": hashes.SHA512,
        }[hash_name]

        signed_attrs = signer_info["signedAttrs"]
        if signed_attrs.isValue:
            # signedAttrs must contain a messageDigest attribute equal to
            # the digest of eContent -- otherwise the signature could
            # cover attributes disconnected from the actual TSTInfo.
            message_digest = None
            for attr in signed_attrs:
                if str(attr["attrType"]) == str(rfc5652.id_messageDigest):
                    values = attr["attrValues"]
                    if len(values) != 1:
                        return False
                    inner, _ = der_decoder.decode(bytes(values[0]))
                    message_digest = bytes(inner)
                    break
            if message_digest is None:
                return False

            digest = hashlib.new(hash_name, econtent).digest()
            if message_digest != digest:
                return False

            # Re-tag signedAttrs from its IMPLICIT [0] context tag to the
            # universal SET tag it must have for signature purposes
            # (RFC 5652 §5.4): the signature covers a DER SET OF Attribute,
            # not the [0]-tagged field as it appears in SignerInfo.
            reencoded_attrs = signed_attrs.clone(
                tagSet=rfc5652.SignedAttributes().tagSet,
                cloneValueFlag=True,
            )
            signed_bytes = der_encoder.encode(reencoded_attrs)
        else:
            signed_bytes = econtent

        signature = bytes(signer_info["signature"])
        public_key = signer_cert.public_key()

        try:
            if isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(
                    signature, signed_bytes, padding.PKCS1v15(), hash_cls()
                )
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                public_key.verify(
                    signature, signed_bytes, ec.ECDSA(hash_cls())
                )
            else:
                return False
        except InvalidSignature:
            return False

        return True

    def _send_request(self, tsa_url: str, req_bytes: bytes) -> bytes:
        """
        Send a TimeStampReq to a TSA and return the raw response.

        Args:
            tsa_url: The TSA endpoint URL.
            req_bytes: DER-encoded TimeStampReq.

        Returns:
            Raw response bytes.

        Raises:
            TimestampError: If the HTTP request fails.
        """
        import urllib.request

        http_req = urllib.request.Request(
            tsa_url,
            data=req_bytes,
            headers={
                "Content-Type": "application/timestamp-query",
                "Accept": "application/timestamp-reply",
            },
            method="POST",
        )

        start = time.monotonic()
        try:
            with urllib.request.urlopen(http_req, timeout=self._timeout) as resp:
                content_length = resp.headers.get("Content-Length")
                if content_length is not None:
                    try:
                        if int(content_length) > MAX_TSA_RESPONSE_BYTES:
                            raise TimestampError(
                                f"TSA response from {tsa_url} declares "
                                f"Content-Length={content_length}, exceeding "
                                f"the {MAX_TSA_RESPONSE_BYTES}-byte limit."
                            )
                    except ValueError:
                        pass
                body = resp.read(MAX_TSA_RESPONSE_BYTES + 1)
                if len(body) > MAX_TSA_RESPONSE_BYTES:
                    raise TimestampError(
                        f"TSA response from {tsa_url} exceeded the "
                        f"{MAX_TSA_RESPONSE_BYTES}-byte limit."
                    )
                return body
        except ssl.SSLError as exc:
            elapsed = time.monotonic() - start
            logger.error(
                "TSA TLS/certificate verification failed: host=%s exc_type=%s "
                "elapsed=%.3fs detail=%s",
                tsa_url, type(exc).__name__, elapsed, exc,
            )
            raise TimestampError(
                f"TSA request to {tsa_url} failed: {exc}"
            ) from exc
        except urllib.error.URLError as exc:
            elapsed = time.monotonic() - start
            logger.warning(
                "TSA request failed: host=%s exc_type=%s elapsed=%.3fs detail=%s",
                tsa_url, type(exc).__name__, elapsed, exc,
            )
            raise TimestampError(
                f"TSA request to {tsa_url} failed: {exc}"
            ) from exc
        except Exception as exc:
            elapsed = time.monotonic() - start
            logger.error(
                "TSA request failed with unexpected error: host=%s exc_type=%s "
                "elapsed=%.3fs detail=%s",
                tsa_url, type(exc).__name__, elapsed, exc,
            )
            raise TimestampError(
                f"TSA request to {tsa_url} failed: {exc}"
            ) from exc

    def stamp(self, data: bytes) -> TimestampToken:
        """
        Obtain an RFC 3161 timestamp for the given data.

        Tries the primary TSA first; falls back to the secondary if the
        primary is unavailable.

        Args:
            data: The raw bytes to timestamp.

        Returns:
            A :class:`TimestampToken` containing the TSA response.

        Raises:
            TimestampError: If both TSAs are unavailable or pyasn1
                is missing.
        """
        if not _PYASN1_AVAILABLE:
            raise TimestampError(
                "pyasn1 is required for RFC 3161 timestamps.  "
                "Install with:  pip install pyasn1"
            )

        req_bytes, nonce_val = self._build_timestamp_request(data)
        digest_hex = hashlib.sha256(data).hexdigest()

        errors: list[str] = []
        for url in (self._tsa_url, self._fallback_url):
            try:
                resp_bytes = self._send_request(url, req_bytes)

                # Parse TSTInfo.nonce and require it to match the nonce we
                # sent. Without this check, a captured/replayed prior
                # TimeStampResp (for potentially different data) cannot be
                # distinguished from a fresh response, letting a malicious
                # or compromised TSA / on-path attacker misattribute a
                # stale time to new data.
                resp_nonce = self._extract_tst_info_nonce(resp_bytes)
                if resp_nonce is None:
                    raise TimestampError(
                        f"TSA response from {url} did not echo the "
                        "request nonce; rejecting to prevent replay."
                    )
                if resp_nonce != nonce_val:
                    raise TimestampError(
                        f"TSA response from {url} echoed nonce "
                        f"{resp_nonce}, expected {nonce_val}; "
                        "possible replay of a stale/substituted response."
                    )

                candidate = TimestampToken(
                    tsa_url=url,
                    token_bytes=resp_bytes,
                    token_hex=resp_bytes.hex(),
                    stamped_at=int(time.time()),
                    hash_algorithm="sha-256",
                    message_imprint=digest_hex,
                )

                # Reject the response outright unless it also passes full
                # verification (status/hash/CMS signature) -- otherwise
                # stamp() would happily persist a token that verify()
                # itself would later reject.
                if not self.verify(data, candidate):
                    raise TimestampError(
                        f"TSA response from {url} failed verification "
                        "(bad status, hash mismatch, or invalid CMS "
                        "signature); rejecting."
                    )

                return candidate
            except TimestampError as exc:
                errors.append(str(exc))
                continue

        raise TimestampError(
            f"All TSA endpoints failed: {'; '.join(errors)}"
        )

    def verify(self, data: bytes, token: TimestampToken) -> bool:
        """
        Verify that a timestamp token matches the given data.

        This performs an actual ASN.1 decode of the TSA's raw response
        (``token.token_bytes``) -- not just a comparison against the
        caller-supplied, self-asserted ``token.message_imprint`` field.
        Specifically it:

        1. Decodes ``token_bytes`` as an RFC 3161 ``TimeStampResp`` and
           confirms the TSA reported a granted status.
        2. Unwraps the embedded CMS ``SignedData`` / ``encapContentInfo``
           to recover the DER-encoded ``TSTInfo`` the TSA actually signed.
        3. Extracts the ``messageImprint.hashedMessage`` field *from that
           TSTInfo* -- i.e. the hash the TSA itself attested to -- and
           requires it to equal ``sha256(data)``.

        4. Verifies the CMS ``SignerInfo`` signature over that ``TSTInfo``
           against the signer certificate embedded in the response,
           proving the response was produced by whoever holds the
           corresponding private key (``_verify_cms_signature``).

        This defeats a malicious/compromised TSA (or network attacker)
        returning arbitrary ``token_bytes`` alongside a self-computed
        ``message_imprint``: without a genuine, correctly-signed TSA
        response whose embedded TSTInfo hash matches the data, verification
        now fails.

        Note: this verifies the CMS signature against the certificate
        embedded in the response itself; it does **not** build/validate a
        full certificate chain to a trusted root store. Pair this with a
        dedicated PKI library (or pin the expected TSA certificate) if a
        full chain-of-trust guarantee is required.

        Args:
            data: The original data that was timestamped.
            token: The :class:`TimestampToken` to verify.

        Returns:
            ``True`` if the TSA's own signed TSTInfo hash matches
            ``sha256(data)`` *and* the CMS signature over that TSTInfo
            verifies against the embedded signer certificate; ``False``
            otherwise (including on any malformed/unparsable response).

        Raises:
            TimestampError: If pyasn1 is not available.
        """
        if not _PYASN1_AVAILABLE:
            raise TimestampError(
                "pyasn1 is required to verify RFC 3161 timestamps.  "
                "Install with:  pip install pyasn1"
            )
        if not _CMS_VERIFY_AVAILABLE:
            raise TimestampError(
                "pyasn1_modules and cryptography are required to verify "
                "RFC 3161 timestamp signatures.  Install with:  "
                "pip install pyasn1_modules cryptography"
            )

        expected_digest = hashlib.sha256(data).digest()

        try:
            resp, _ = der_decoder.decode(token.token_bytes, asn1Spec=TimeStampResp())

            status = int(resp.getComponentByName("status").getComponentByName("status"))
            if status not in (0, 1):  # 0=granted, 1=grantedWithMods
                return False

            content_info = resp.getComponentByName("timeStampToken")
            if content_info is None or not content_info.hasValue():
                return False

            signed_data_der = bytes(content_info.getComponentByName("content"))
            signed_data, _ = der_decoder.decode(
                signed_data_der, asn1Spec=SignedData()
            )

            econtent = signed_data.getComponentByName(
                "encapContentInfo"
            ).getComponentByName("eContent")
            if econtent is None or not econtent.hasValue():
                return False

            tst_info, _ = der_decoder.decode(bytes(econtent), asn1Spec=TSTInfo())
            tsa_hashed_message = bytes(
                tst_info.getComponentByName("messageImprint").getComponentByName(
                    "hashedMessage"
                )
            )
        except Exception:
            # Malformed/unparsable TSA response -- cannot be trusted.
            return False

        if tsa_hashed_message != expected_digest:
            return False

        # Sanity-check the locally recorded imprint is consistent too.
        if token.message_imprint != expected_digest.hex():
            return False

        # Finally, verify the CMS signature covering that TSTInfo against
        # the embedded signer certificate. Without this, an attacker could
        # forge a well-formed but unsigned/self-authored TimeStampResp with
        # the correct hash and status, and it would pass every check above.
        return self._verify_cms_signature(signed_data_der)
