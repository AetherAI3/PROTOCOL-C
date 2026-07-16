"""
Regression tests for aether_protocol_c/ephemeral_signer.py (F-21).

destroy() is documented as "zeroing" private key material. Prior to the
fix, it only did `self._privkey = 0`, which -- because Python ints are
immutable -- merely rebinds the attribute to a new int object and leaves
the original private-key bytes untouched on the heap. These tests verify
that destroy() now overwrites the actual backing buffer in place.
"""

from aether_protocol_c.ephemeral_signer import EphemeralSigner


def test_destroy_zeroes_the_private_key_backing_buffer():
    # Arrange
    signer = EphemeralSigner(quantum_seed=0xABCDEF)
    privkey_buf_before = signer._privkey_buf
    assert any(b != 0 for b in privkey_buf_before), (
        "sanity check: private key buffer should be non-zero before destroy()"
    )

    # Act
    signer.destroy()

    # Assert: the SAME buffer object (not a new one) is now all zero bytes --
    # this is the property a bare `self._privkey = 0` rebind could never
    # satisfy, since it never touches the original object's memory at all.
    assert privkey_buf_before is signer._privkey_buf
    assert all(b == 0 for b in signer._privkey_buf)


def test_destroy_makes_privkey_property_read_as_zero():
    # Arrange
    signer = EphemeralSigner(quantum_seed=0x123456)

    # Act
    signer.destroy()

    # Assert
    assert signer._privkey == 0


def test_init_wipes_intermediate_seed_and_key_material_copies():
    # Arrange / Act
    signer = EphemeralSigner(quantum_seed=0x999999)

    # Assert: __init__ must not leave live, non-zeroed references to the
    # intermediate seed_bytes/key_material buffers hanging off the instance.
    assert not hasattr(signer, "_seed_bytes")
    assert not hasattr(signer, "_key_material")
