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
import os
import time
from dataclasses import dataclass
from typing import Optional

try:
    from pyasn1.type import univ, namedtype, tag, useful, constraint
    from pyasn1.codec.der import encoder as der_encoder
    from pyasn1.codec.der import decoder as der_decoder
    _PYASN1_AVAILABLE = True
except ImportError:
    _PYASN1_AVAILABLE = False


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
            namedtype.OptionalNamedType(
                "crls",
                univ.Any().subtype(
                    implicitTag=tag.Tag(
                        tag.tagClassContext, tag.tagFormatConstructed, 1
                    )
                ),
            ),
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

    def _build_timestamp_request(self, data: bytes) -> bytes:
        """
        Build a DER-encoded RFC 3161 TimeStampReq for the given data.

        Args:
            data: The raw bytes to timestamp.

        Returns:
            DER-encoded TimeStampReq bytes.

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

        return der_encoder.encode(req)

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

        try:
            with urllib.request.urlopen(http_req, timeout=self._timeout) as resp:
                return resp.read()
        except Exception as exc:
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
        req_bytes = self._build_timestamp_request(data)
        digest_hex = hashlib.sha256(data).hexdigest()

        errors: list[str] = []
        for url in (self._tsa_url, self._fallback_url):
            try:
                resp_bytes = self._send_request(url, req_bytes)
                return TimestampToken(
                    tsa_url=url,
                    token_bytes=resp_bytes,
                    token_hex=resp_bytes.hex(),
                    stamped_at=int(time.time()),
                    hash_algorithm="sha-256",
                    message_imprint=digest_hex,
                )
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

        This defeats a malicious/compromised TSA (or network attacker)
        returning arbitrary ``token_bytes`` alongside a self-computed
        ``message_imprint``: without a genuine TSA response whose embedded
        TSTInfo hash matches the data, verification now fails.

        Note: this does **not** verify the CMS ``SignerInfo`` signature or
        the TSA certificate chain -- it only cryptographically parses and
        checks the content the signature covers.  For full trust-chain
        verification, pair this with a dedicated PKI/CMS library.

        Args:
            data: The original data that was timestamped.
            token: The :class:`TimestampToken` to verify.

        Returns:
            ``True`` if the TSA's own signed TSTInfo hash matches
            ``sha256(data)``; ``False`` otherwise (including on any
            malformed/unparsable response).

        Raises:
            TimestampError: If pyasn1 is not available.
        """
        if not _PYASN1_AVAILABLE:
            raise TimestampError(
                "pyasn1 is required to verify RFC 3161 timestamps.  "
                "Install with:  pip install pyasn1"
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
        return token.message_imprint == expected_digest.hex()
