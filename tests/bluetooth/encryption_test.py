import unittest

from bluetti_bt_lib.bluetooth.encryption import (
    BluettiEncryption,
    KEX_MAGIC,
    Message,
    hexsum,
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
