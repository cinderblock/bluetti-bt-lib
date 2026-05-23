import unittest

from cryptography.exceptions import InvalidSignature

from bluetti_bt_lib.bluetooth.encryption import (
    BluettiEncryption,
    KEX_MAGIC,
    Message,
    MessageType,
    hexsum,
    verify_and_extract_signed_data,
)


class TestBluettiEncryptionReset(unittest.TestCase):
    def test_reset_clears_all_handshake_state(self):
        enc = BluettiEncryption()

        enc.unsecure_aes_key = b"\x00" * 16
        enc.unsecure_aes_iv = b"\x01" * 16
        enc.secure_aes_key = b"\x02" * 32
        enc.peer_pubkey = object()
        enc.my_pubkey = object()
        enc.my_privkey = object()

        enc.reset()

        self.assertIsNone(enc.unsecure_aes_key)
        self.assertIsNone(enc.unsecure_aes_iv)
        self.assertIsNone(enc.secure_aes_key)
        self.assertIsNone(enc.peer_pubkey)
        self.assertIsNone(enc.my_pubkey)
        self.assertIsNone(enc.my_privkey)

    def test_two_instances_have_independent_state(self):
        a = BluettiEncryption()
        b = BluettiEncryption()

        a.unsecure_aes_iv = b"\xaa" * 16

        self.assertIsNone(b.unsecure_aes_iv)

    def test_is_ready_for_commands_false_by_default(self):
        enc = BluettiEncryption()
        self.assertFalse(enc.is_ready_for_commands)


class TestMessageVerifyChecksum(unittest.TestCase):
    def _build(self, body: bytes) -> Message:
        return Message(KEX_MAGIC + body + hexsum(body, 2))

    def test_returns_true_on_valid_checksum(self):
        # body = type(0x01) + len(0x04) + 4 bytes payload
        message = self._build(b"\x01\x04\xaa\xbb\xcc\xdd")
        self.assertTrue(message.verify_checksum())

    def test_returns_false_on_bad_checksum(self):
        body = b"\x01\x04\xaa\xbb\xcc\xdd"
        bad = Message(KEX_MAGIC + body + b"\x00\x00")
        self.assertFalse(bad.verify_checksum())


class TestMessageType(unittest.TestCase):
    def _build(self, body: bytes) -> Message:
        return Message(KEX_MAGIC + body + hexsum(body, 2))

    def test_known_type(self):
        message = self._build(b"\x01\x04\xaa\xbb\xcc\xdd")
        self.assertEqual(message.type, MessageType.CHALLENGE)

    def test_unknown_type_returns_none(self):
        # 0x09 is not a defined MessageType — must not raise.
        message = self._build(b"\x09\x04\xaa\xbb\xcc\xdd")
        self.assertIsNone(message.type)


class TestVerifyAndExtractSignedData(unittest.TestCase):
    """Bluetti firmware sometimes strips a leading 0x00 from r or s and pads
    with a trailing 0x00. The verifier must accept all three layouts so the
    handshake succeeds reliably (the canonical 32|32 split alone only works
    for ~25% of signatures — when both r and s have their high bit set)."""

    # Real triples captured from an AP300 on HA. The pubkey is the device's
    # ephemeral ECDH public key, iv is the unsecure_aes_iv (MD5 of reversed
    # challenge data), and signature is the device's ECDSA signature over
    # pubkey||iv, signed with the well-known PRIVATE_KEY_L1 / verified by
    # PUBLIC_KEY_K2.
    #
    # Layout (b): r encoded as 31 bytes (high-bit-clear in r[0])
    CAPTURE_R31 = {
        "pubkey":    "ad68a0c1ec1ff8814a6024885cf0d23410fdaba7f82b54d8d3ddc54a6736d441"
                     "8c495829bd7f2a0ee8645f4fb7431689c8170575f3b96e8e4e9d60ca6b21c256",
        "iv":        "25ab6cb9ec675e644256d8108db50f19",
        "signature": "50be7b46ab930f30810d7f47fb51e91ad53c773702fc951d4905169f3ade878f"
                     "653ce06f3bdd63782476e91cf59ab0008097a8cc2004f5d2bc9ed4c9dae6bc00",
    }
    # Layout (c): s encoded as 31 bytes (with trailing pad — sig[0] high bit
    # is also set so neither (a) nor (b) works; only (c) does)
    CAPTURE_S31 = {
        "pubkey":    "2ee32d3b3ab9d1b24fe98c6ee938014082a5625802bec340e1f04b121cb54515"
                     "5317456a5ba5e2189f82222a0936e57020408ea9ea9db09b9c95ab314422e095",
        "iv":        "c643ae110bc0efc51d0caf4493797b45",
        "signature": "d2a14f26257869073c59e64047db6cc5923ef307a9e1c6e9cfd44e7fa0fc3233"
                     "b45b50f9319add2aa57d1b88ce5ae210e2aad652130c6f666e3b1f92b052d500",
    }

    def _verify(self, triple):
        message = bytes.fromhex(triple["pubkey"]) + bytes.fromhex(triple["signature"])
        iv = bytes.fromhex(triple["iv"])
        return verify_and_extract_signed_data(memoryview(message), iv)

    def test_layout_b_r_is_31_bytes(self):
        data = self._verify(self.CAPTURE_R31)
        self.assertEqual(data.tobytes().hex(), self.CAPTURE_R31["pubkey"])

    def test_layout_c_s_is_31_bytes(self):
        data = self._verify(self.CAPTURE_S31)
        self.assertEqual(data.tobytes().hex(), self.CAPTURE_S31["pubkey"])

    def test_tampered_signature_rejected(self):
        triple = dict(self.CAPTURE_R31)
        sig = bytearray.fromhex(triple["signature"])
        sig[5] ^= 0xFF
        triple["signature"] = sig.hex()
        with self.assertRaises(InvalidSignature):
            self._verify(triple)

    def test_wrong_iv_rejected(self):
        triple = dict(self.CAPTURE_R31)
        iv = bytearray.fromhex(triple["iv"])
        iv[0] ^= 0xFF
        triple["iv"] = iv.hex()
        with self.assertRaises(InvalidSignature):
            self._verify(triple)

    def test_zero_signature_rejected(self):
        triple = dict(self.CAPTURE_R31)
        triple["signature"] = "00" * 64
        with self.assertRaises(InvalidSignature):
            self._verify(triple)
