import unittest

from bluetti_bt_lib.bluetooth.encryption import BluettiEncryption


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
