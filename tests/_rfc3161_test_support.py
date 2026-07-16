"""
tests/_rfc3161_test_support.py

Shared test-only helpers for building real, decodable RFC 3161
``TimeStampResp`` / CMS ``SignedData`` fixtures, optionally with a genuine
CMS signature over a self-signed TSA certificate.

Not a test module itself -- imported by the ``test_timestamp_authority_*``
files. Requires ``cryptography`` in addition to ``pyasn1``.
"""

from __future__ import annotations

import datetime
import hashlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.type import tag, univ, useful

_SHA256_OID = univ.ObjectIdentifier((2, 16, 840, 1, 101, 3, 4, 2, 1))
_TST_INFO_OID = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 9, 16, 1, 4))
_RSA_OID = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 1, 1))
_SIGNED_DATA_OID = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 7, 2))
_CONTENT_TYPE_OID = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 9, 3))
_MESSAGE_DIGEST_OID = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 9, 4))


def generate_self_signed_tsa_cert():
    """Generate a throwaway RSA key + self-signed certificate for a fake TSA."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test TSA")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(12345)
        .not_valid_before(datetime.datetime(2020, 1, 1))
        .not_valid_after(datetime.datetime(2030, 1, 1))
        .sign(key, hashes.SHA256())
    )
    return key, cert


def build_tst_info_der(digest: bytes, nonce=None) -> bytes:
    """Build a minimal DER-encoded TSTInfo whose messageImprint == digest,
    optionally echoing ``nonce`` (as a genuine TSA response would)."""
    algo_seq = univ.Sequence()
    algo_seq.setComponentByPosition(0, _SHA256_OID)
    imprint = univ.Sequence()
    imprint.setComponentByPosition(0, algo_seq)
    imprint.setComponentByPosition(1, univ.OctetString(digest))

    tst_info = univ.Sequence()
    tst_info.setComponentByPosition(0, univ.Integer(1))  # version
    tst_info.setComponentByPosition(1, univ.ObjectIdentifier((1, 2, 3)))  # policy
    tst_info.setComponentByPosition(2, imprint)
    tst_info.setComponentByPosition(3, univ.Integer(1))  # serialNumber
    tst_info.setComponentByPosition(4, useful.GeneralizedTime("20260101000000Z"))
    if nonce is not None:
        # Per DER, a component with its DEFAULT value ("ordering" defaults
        # to FALSE) must be omitted from the encoding, matching how a
        # real, DER-compliant TSA would encode this. `accuracy` is also
        # OPTIONAL and omitted, so `nonce` is set at position 5 (not 6).
        tst_info.setComponentByPosition(5, univ.Integer(nonce))
    return der_encoder.encode(tst_info)


def _build_attribute(oid: univ.ObjectIdentifier, value_der: bytes) -> univ.Sequence:
    attr = univ.Sequence()
    attr.setComponentByPosition(0, oid)
    values = univ.SetOf(componentType=univ.Any())
    values.setComponentByPosition(0, univ.Any(value_der))
    attr.setComponentByPosition(1, values)
    return attr


def build_signed_timestamp_resp_der(
    digest: bytes,
    key,
    cert,
    *,
    tst_info_der=None,
    corrupt_signature: bool = False,
    status: int = 0,
) -> bytes:
    """
    Build a full, decodable RFC 3161 ``TimeStampResp`` whose embedded
    ``TSTInfo`` genuinely attests to ``digest``, wrapped in a real CMS
    ``SignedData`` signed (RSA/PKCS#1v1.5/SHA-256) with ``key`` over a
    ``signedAttrs`` set, alongside the self-signed ``cert``.

    Args:
        digest: The SHA-256 digest the TSTInfo's messageImprint attests to.
        key: RSA private key used to sign the CMS ``signedAttrs``.
        cert: Self-signed certificate embedded in the CMS ``SignedData``
            (must correspond to ``key``).
        tst_info_der: Pre-built TSTInfo DER to use instead of building one
            from ``digest`` (e.g. to test a digest/TSTInfo mismatch).
        corrupt_signature: If True, flip a bit in the CMS signature bytes
            so the response has correct hash/status but an invalid
            signature.

    Returns:
        DER-encoded ``TimeStampResp`` bytes.
    """
    if tst_info_der is None:
        tst_info_der = build_tst_info_der(digest)
    econtent_digest = hashlib.sha256(tst_info_der).digest()

    attr_content_type = _build_attribute(
        _CONTENT_TYPE_OID, der_encoder.encode(_TST_INFO_OID)
    )
    attr_message_digest = _build_attribute(
        _MESSAGE_DIGEST_OID, der_encoder.encode(univ.OctetString(econtent_digest))
    )

    signed_attrs_set = univ.SetOf(componentType=univ.Sequence())
    signed_attrs_set.setComponentByPosition(0, attr_content_type)
    signed_attrs_set.setComponentByPosition(1, attr_message_digest)
    signed_attrs_der_for_signing = der_encoder.encode(signed_attrs_set)
    signature = key.sign(
        signed_attrs_der_for_signing, padding.PKCS1v15(), hashes.SHA256()
    )
    if corrupt_signature:
        signature = bytes(signature[:-1]) + bytes([signature[-1] ^ 0xFF])

    issuer_name_der = cert.issuer.public_bytes()
    issuer_and_serial = univ.Sequence()
    issuer_and_serial.setComponentByPosition(0, univ.Any(issuer_name_der))
    issuer_and_serial.setComponentByPosition(1, univ.Integer(cert.serial_number))

    digest_algo = univ.Sequence()
    digest_algo.setComponentByPosition(0, _SHA256_OID)

    signer_info = univ.Sequence()
    signer_info.setComponentByPosition(0, univ.Integer(1))  # version
    signer_info.setComponentByPosition(1, issuer_and_serial)  # sid
    signer_info.setComponentByPosition(2, digest_algo)
    signed_attrs_implicit = signed_attrs_set.subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0),
        cloneValueFlag=True,
    )
    signer_info.setComponentByPosition(3, signed_attrs_implicit)
    sig_algo = univ.Sequence()
    sig_algo.setComponentByPosition(0, _RSA_OID)
    signer_info.setComponentByPosition(4, sig_algo)
    signer_info.setComponentByPosition(5, univ.OctetString(signature))

    signer_infos = univ.SetOf(componentType=univ.Any())
    signer_infos.setComponentByPosition(0, univ.Any(der_encoder.encode(signer_info)))

    digest_algos = univ.SetOf(componentType=univ.Sequence())
    digest_algos.setComponentByPosition(0, digest_algo)

    econtent_val = univ.OctetString(tst_info_der).subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
    )
    encap_content_info = univ.Sequence()
    encap_content_info.setComponentByPosition(0, _TST_INFO_OID)
    encap_content_info.setComponentByPosition(1, econtent_val)

    cert_der = cert.public_bytes(serialization.Encoding.DER)
    certs_set = univ.SetOf(componentType=univ.Any())
    certs_set.setComponentByPosition(0, univ.Any(cert_der))
    certs_implicit = certs_set.subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0),
        cloneValueFlag=True,
    )

    signed_data = univ.Sequence()
    signed_data.setComponentByPosition(0, univ.Integer(3))
    signed_data.setComponentByPosition(1, digest_algos)
    signed_data.setComponentByPosition(2, encap_content_info)
    signed_data.setComponentByPosition(3, certs_implicit)
    signed_data.setComponentByPosition(4, signer_infos)
    signed_data_der = der_encoder.encode(signed_data)

    return _wrap_signed_data_in_resp(signed_data_der, status=status)


def build_unsigned_timestamp_resp_der(digest: bytes) -> bytes:
    """
    Build a well-formed ``TimeStampResp`` with a granted status and a
    ``TSTInfo`` whose messageImprint genuinely equals ``digest``, but with
    **no** CMS signerInfos/certificates at all.

    This is the core F-7 regression fixture: pre-fix, this passed
    ``verify()`` because only the hash was checked; post-fix it must be
    rejected because there is no cryptographic signature over it.
    """
    tst_info_der = build_tst_info_der(digest)

    econtent_val = univ.OctetString(tst_info_der).subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
    )
    encap_content_info = univ.Sequence()
    encap_content_info.setComponentByPosition(0, _TST_INFO_OID)
    encap_content_info.setComponentByPosition(1, econtent_val)

    empty_certs = univ.SetOf(componentType=univ.Any()).subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
    )

    signed_data = univ.Sequence()
    signed_data.setComponentByPosition(0, univ.Integer(3))
    signed_data.setComponentByPosition(1, univ.SetOf(componentType=univ.Sequence()))
    signed_data.setComponentByPosition(2, encap_content_info)
    signed_data.setComponentByPosition(3, empty_certs)
    signed_data.setComponentByPosition(4, univ.SetOf(componentType=univ.Any()))
    signed_data_der = der_encoder.encode(signed_data)

    return _wrap_signed_data_in_resp(signed_data_der)


def _wrap_signed_data_in_resp(signed_data_der: bytes, status: int = 0) -> bytes:
    content_wrapped = univ.Any(signed_data_der).subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
    )
    content_info = univ.Sequence()
    content_info.setComponentByPosition(0, _SIGNED_DATA_OID)
    content_info.setComponentByPosition(1, content_wrapped)

    status_info = univ.Sequence()
    status_info.setComponentByPosition(0, univ.Integer(status))  # 0=granted, 1=grantedWithMods

    resp = univ.Sequence()
    resp.setComponentByPosition(0, status_info)
    resp.setComponentByPosition(1, content_info)

    return der_encoder.encode(resp)
