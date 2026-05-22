import asyncio
import logging
import async_timeout
from typing import Any, Callable, List, cast
from bleak import BleakClient, BleakScanner
from bleak.exc import BleakError
from bleak_retry_connector import (
    BleakClientWithServiceCache,
    BleakNotFoundError,
    BleakAbortedError,
    BleakConnectionError,
    BleakOutOfConnectionSlotsError,
    establish_connection,
)

from cryptography.exceptions import InvalidSignature

from .encryption import BluettiEncryption, Message, MessageType
from .exceptions import (
    DeviceNotFoundError,
    ConnectionFailedError,
    EncryptionHandshakeError,
)
from ..base_devices import BluettiDevice
from ..const import NOTIFY_UUID, WRITE_UUID
from ..registers import ReadableRegisters, DeviceRegister
from ..utils.privacy import mac_loggable


class DeviceReaderConfig:
    def __init__(self, timeout: int = 60, use_encryption: bool = False):
        self.timeout = timeout
        self.use_encryption = use_encryption


class DeviceReader:
    def __init__(
        self,
        mac: str,
        bluetti_device: BluettiDevice,
        future_builder_method: Callable[[], asyncio.Future[Any]],
        config: DeviceReaderConfig = DeviceReaderConfig(),
        lock: asyncio.Lock = asyncio.Lock(),
        ble_client: BleakClient | None = None,
    ):
        self.mac = mac
        self.bluetti_device = bluetti_device
        self.create_future = future_builder_method
        self.config = config
        self.polling_lock = lock

        self.ble_client = ble_client
        """Used for unittests"""

        self.logger = logging.getLogger(
            f"{__name__}.{mac_loggable(mac).replace(':', '_')}"
        )

        self.device = None
        self.client = None

        self.has_notifier = False
        self.current_registers = None
        self.notify_response = bytearray()
        self.notify_future: asyncio.Future[Any] | None = None
        self.encryption = BluettiEncryption()

    async def read(
        self, only_registers: List[ReadableRegisters] | None = None, raw: bool = False
    ) -> dict | None:

        registers = self.bluetti_device.get_polling_registers()
        pack_registers = self.bluetti_device.get_pack_polling_registers()

        if only_registers is not None:
            registers = only_registers
            pack_registers = []

        parsed_data: dict = {}

        self.logger.debug("Reading device registers")

        async with self.polling_lock:
            # Start every read from a clean handshake state so a partial
            # handshake from a previous attempt cannot leak stale IV/keys
            # into this session.
            self.encryption.reset()

            try:
                async with async_timeout.timeout(self.config.timeout):
                    # Stage 1: Scan for device
                    self.logger.debug("Searching for device")

                    if self.ble_client:
                        self.device = None
                    else:
                        self.device = await BleakScanner.find_device_by_address(
                            self.mac, timeout=5
                        )

                        if self.device is None:
                            raise DeviceNotFoundError(
                                f"Device {mac_loggable(self.mac)} not found. "
                                "The device may be out of range or powered off."
                            )

                    # Stage 2: Connect
                    self.logger.debug("Connecting to device")

                    if self.ble_client:
                        self.client = self.ble_client
                    else:
                        try:
                            self.client = await establish_connection(
                                BleakClientWithServiceCache,
                                self.device,
                                self.device.name or "Unknown Device",
                                max_attempts=3,
                            )
                        except (
                            BleakNotFoundError,
                            BleakAbortedError,
                            BleakConnectionError,
                            BleakOutOfConnectionSlotsError,
                            BleakError,
                        ) as err:
                            raise ConnectionFailedError(
                                f"Device {mac_loggable(self.mac)} was found but the "
                                "connection failed. Another Bluetooth client (such as "
                                "the Bluetti app) may already be connected. "
                                "Disconnect any other Bluetooth clients and try again."
                            ) from err

                    self.logger.debug("Connected to device")

                    # Stage 3: Subscribe to notifications
                    try:
                        if not self.has_notifier:
                            await self.client.start_notify(
                                NOTIFY_UUID, self._notification_handler
                            )
                            self.has_notifier = True
                    except BleakError as err:
                        raise ConnectionFailedError(
                            f"Device {mac_loggable(self.mac)} connected but failed "
                            "to subscribe to notifications."
                        ) from err

                    self.logger.debug("Notification handler setup complete")

                    # Stage 4: Encryption handshake
                    if self.config.use_encryption:
                        handshake_timeout = 30
                        elapsed = 0
                        while not self.encryption.is_ready_for_commands:
                            if elapsed >= handshake_timeout:
                                raise EncryptionHandshakeError(
                                    f"Device {mac_loggable(self.mac)} connected but "
                                    "the encryption handshake failed. This may "
                                    "indicate a library bug. Please open an issue at "
                                    "https://github.com/Patrick762/bluetti-bt-lib/issues "
                                    "with your device model and firmware version."
                                )
                            await asyncio.sleep(2)
                            elapsed += 2
                            self.logger.debug(
                                "Encryption handshake not finished yet"
                            )

                    # Stage 5: Read registers
                    for register in registers:
                        body = register.parse_response(
                            await self._async_send_command(register)
                        )

                        self.logger.debug("Raw data: %s", body)

                        if raw:
                            d = {}
                            d[register.starting_address] = body
                            parsed_data.update(d)
                            continue

                        parsed = self.bluetti_device.parse(
                            register.starting_address, body
                        )

                        self.logger.debug("Parsed data: %s", parsed)

                        parsed_data.update(parsed)

                    for pack in range(1, self.bluetti_device.max_packs + 1):
                        body = register.parse_response(
                            await self._async_send_command(
                                self.bluetti_device.get_pack_selector(pack),
                            )
                        )

                        # We need to wait for the powerstation to populate all registers
                        await asyncio.sleep(3)

                        for register in pack_registers:
                            body = register.parse_response(
                                await self._async_send_command(register)
                            )

                            self.logger.debug("Raw data: %s", body)

                            if raw:
                                d = {}
                                d[register.starting_address] = body
                                parsed_data.update(d)
                                continue

                            parsed = self.bluetti_device.parse(
                                register.starting_address,
                                body,
                                pack_num=pack,
                            )

                            self.logger.debug("Parsed data: %s", parsed)

                            parsed_data.update(parsed)

            except (
                DeviceNotFoundError,
                ConnectionFailedError,
                EncryptionHandshakeError,
            ):
                raise
            except TimeoutError:
                raise ConnectionFailedError(
                    f"Device {mac_loggable(self.mac)} communication timed out "
                    f"after {self.config.timeout}s. Another Bluetooth client "
                    "(such as the Bluetti app) may already be connected."
                )
            except BleakError as err:
                raise ConnectionFailedError(
                    f"Device {mac_loggable(self.mac)} Bluetooth error: {err}"
                ) from err
            except Exception as err:
                self.logger.error(
                    "Unexpected error communicating with %s: %s",
                    mac_loggable(self.mac),
                    err,
                )
                raise
            finally:
                if self.has_notifier:
                    try:
                        await self.client.stop_notify(NOTIFY_UUID)
                        self.logger.debug("Stopped notifier")
                    except:
                        # Ignore errors here
                        pass
                    self.has_notifier = False
                if self.client:
                    await self.client.disconnect()
                    self.logger.debug("Disconnected from device")
                # Always reset encryption state, even on exception, so a
                # partial handshake never leaks into the next read.
                self.encryption.reset()

            # Check if dict is empty
            if not parsed_data:
                return None

            parsed_data.update(self.bluetti_device.derive(parsed_data))
            return parsed_data

    async def _async_send_command(self, registers: DeviceRegister) -> bytes:
        """Send command and return response"""
        self.current_registers = registers
        self.notify_response = bytearray()
        self.notify_future = self.create_future()

        command_bytes = bytes(registers)

        # Encrypt command
        if self.config.use_encryption is True:
            if not self.encryption.is_ready_for_commands:
                return bytes()
            command_bytes = self.encryption.aes_encrypt(
                command_bytes, self.encryption.secure_aes_key, None
            )

        try:
            # Make request
            await self.client.write_gatt_char(WRITE_UUID, command_bytes)

            self.logger.debug("Request sent (%s)", registers)

            # Wait for response
            res = await asyncio.wait_for(self.notify_future, timeout=5)

            self.logger.debug("Got response")

            return cast(bytes, res)
        except:
            self.logger.warning("Error while reading data")

        return bytes()

    async def _notification_handler(self, _: int, data: bytearray):
        """Handle bt data."""
        self.logger.debug("Got new data")

        if self.config.use_encryption is True:
            message = Message(data)

            if message.is_pre_key_exchange:
                if not message.verify_checksum():
                    return

                if message.type == MessageType.CHALLENGE:
                    challenge_response = self.encryption.msg_challenge(message)
                    await self.client.write_gatt_char(WRITE_UUID, challenge_response)
                    return

                if message.type == MessageType.CHALLENGE_ACCEPTED:
                    self.logger.debug("Challenge accepted")
                    return

            if self.encryption.unsecure_aes_key is None:
                # No CHALLENGE has been processed yet on this connection, so
                # we can't decrypt anything. This happens when the device
                # sends a queued/unsolicited notification before initiating
                # the handshake. Drop it and wait for CHALLENGE.
                self.logger.debug(
                    "Dropping pre-handshake notification (%d bytes) — "
                    "waiting for CHALLENGE",
                    len(message.buffer),
                )
                return

            key, iv = self.encryption.getKeyIv()
            try:
                decrypted = Message(
                    self.encryption.aes_decrypt(message.buffer, key, iv)
                )
            except ValueError as err:
                # Malformed encrypted frame (wrong length, misaligned, etc.).
                # Don't let it surface as a task-exception in bleak; just drop
                # the frame and let the handshake timeout drive the retry.
                self.logger.warning(
                    "Failed to decrypt notification (%d bytes) for %s: %s",
                    len(message.buffer),
                    mac_loggable(self.mac),
                    err,
                )
                return

            if decrypted.is_pre_key_exchange:
                if not decrypted.verify_checksum():
                    return

                if decrypted.type == MessageType.PEER_PUBKEY:
                    try:
                        peer_pubkey_response = self.encryption.msg_peer_pubkey(
                            decrypted
                        )
                    except InvalidSignature:
                        # Peer pubkey verification failed — most likely a stale
                        # handshake message or a device firmware change. Log
                        # and let the read() handshake timeout drive the retry;
                        # raising here would only surface as a noisy task-
                        # exception in the bleak notification callback.
                        self.logger.warning(
                            "Peer pubkey signature verification failed for %s; "
                            "abandoning this handshake attempt",
                            mac_loggable(self.mac),
                        )
                        self.encryption.reset()
                        return
                    await self.client.write_gatt_char(WRITE_UUID, peer_pubkey_response)
                    return

                if decrypted.type == MessageType.PUBKEY_ACCEPTED:
                    self.encryption.msg_key_accepted(decrypted)
                    return

            # Handle as message
            data = decrypted.buffer

        # Save data
        self.notify_response.extend(data)

        if self.notify_future is None:
            return

        self.notify_future.set_result(self.notify_response)
