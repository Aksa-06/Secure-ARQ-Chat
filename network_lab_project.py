"""
Secure ARQ Messaging System — Stop-and-Wait Edition
=====================================================
Layer Map:
  [Application]  : XOR Encryption (CryptoManager)
  [Transport]    : Stop-and-Wait ARQ (SAWClient)
                   - Sender transmits ONE frame and waits for ACK/NACK
                   - Receiver sends ACK on success, NACK on error
  [Data Link]    : Custom Binary Framing + CRC-16 (ProtocolHandler)
  [Physical]     : UDP Sockets (RelayServer)

Additions (non-protocol):
  - SET CORRUPT on/off  : Server-side bit flip to demo NACK live
  - MAX_RETRIES         : Stops infinite retransmission after N attempts
  - Input validation    : Guards empty/oversized SEND messages
  - SHOW STATS alias    : Both STATS and SHOW STATS work
"""

import socket
import threading
import time
import random
import struct
import binascii
import os
from enum import Enum
from typing import Dict, List, Tuple

# ================================================================
# GLOBAL CONFIGURATION (Runtime Modifiable)
# ================================================================
SERVER_PORT = 5000
MAX_BUFFER  = 4096
MAX_SEQ     = 256        # Sequence numbers wrap at 256
MAX_RETRIES = 5          # Maximum retransmission attempts before giving up
MAX_MSG_LEN = 512        # Maximum message length in characters


class NetConfig:
    LOSS_RATE          = 0.0
    LATENCY_MS         = 0.0
    TIMEOUT            = 2.0
    ENCRYPTION_ENABLED = True
    CORRUPT_ENABLED    = False   # [NEW] When True, server flips a byte to trigger NACK demo

    @staticmethod
    def show():
        print("\n--- CURRENT CONFIGURATION ---")
        print(f"  Loss Rate    : {NetConfig.LOSS_RATE}")
        print(f"  Latency (ms) : {NetConfig.LATENCY_MS}")
        print(f"  Timeout (sec): {NetConfig.TIMEOUT}")
        print(f"  Encryption   : {'ON' if NetConfig.ENCRYPTION_ENABLED else 'OFF'}")
        print(f"  Corruption   : {'ON (NACK demo active)' if NetConfig.CORRUPT_ENABLED else 'OFF'}")
        print(f"  Max Retries  : {MAX_RETRIES}")
        print("------------------------------\n")


# ================================================================
# APPLICATION LAYER: XOR ENCRYPTION
# ================================================================
class CryptoManager:
    """XOR cipher keyed on channel ID — application-layer E2E encryption."""

    @staticmethod
    def _derive_key(channel_id: str) -> bytes:
        return binascii.hexlify(channel_id.encode())[:16]

    @staticmethod
    def encrypt(plaintext: str, channel_id: str) -> bytes:
        if not NetConfig.ENCRYPTION_ENABLED:
            return plaintext.encode()
        key = CryptoManager._derive_key(channel_id)
        return bytes(ord(plaintext[i]) ^ key[i % len(key)] for i in range(len(plaintext)))

    @staticmethod
    def decrypt(ciphertext: bytes, channel_id: str) -> str:
        if not NetConfig.ENCRYPTION_ENABLED:
            return ciphertext.decode(errors="ignore")
        key = CryptoManager._derive_key(channel_id)
        return bytes(
            ciphertext[i] ^ key[i % len(key)] for i in range(len(ciphertext))
        ).decode(errors="ignore")


# ================================================================
# DATA LINK LAYER: FRAMING + CRC-16
# ================================================================
class FrameType(Enum):
    DATA   = 0   # Carries message payload
    ACK    = 1   # Positive acknowledgement — frame received correctly
    NACK   = 2   # Negative acknowledgement — frame corrupted, resend
    JOIN   = 3
    CREATE = 4
    LEAVE  = 5


class ProtocolHandler:
    """
    Frame format (big-endian):
      3 bytes — channel ID (binary)
      1 byte  — frame type
      4 bytes — sequence number (uint32)
      2 bytes — CRC-16 of payload
      N bytes — payload
    Total header = 10 bytes
    """
    HEADER_FORMAT = "!3sBIH"

    @staticmethod
    def compute_crc(data: bytes) -> int:
        """CRC-16 checksum for error detection."""
        return binascii.crc_hqx(data, 0xFFFF)

    @staticmethod
    def create_frame(channel_id: str, frame_type: FrameType,
                     seq_no: int, payload: bytes) -> bytes:
        channel_id    = channel_id.strip().upper().zfill(6)
        channel_bytes = binascii.unhexlify(channel_id)
        seq_no        = seq_no % MAX_SEQ
        crc           = ProtocolHandler.compute_crc(payload)
        header        = struct.pack(ProtocolHandler.HEADER_FORMAT,
                                    channel_bytes, frame_type.value, seq_no, crc)
        return header + payload

    @staticmethod
    def parse_frame(frame: bytes) -> Tuple[str, FrameType, int, bytes]:
        hdr_size = struct.calcsize(ProtocolHandler.HEADER_FORMAT)
        if len(frame) < hdr_size:
            raise ValueError("Frame too short")
        header, payload = frame[:hdr_size], frame[hdr_size:]
        channel_bytes, f_type, seq_no, recv_crc = struct.unpack(
            ProtocolHandler.HEADER_FORMAT, header)
        if ProtocolHandler.compute_crc(payload) != recv_crc:
            raise ValueError("CRC mismatch")
        channel_id = binascii.hexlify(channel_bytes).decode().upper()
        return channel_id, FrameType(f_type), seq_no % MAX_SEQ, payload


# ================================================================
# RELAY SERVER
# ================================================================
class RelayServer:
    """
    UDP relay hub.
    - Maintains named channels with member address lists.
    - Relays DATA / ACK / NACK frames to all other channel members.
    - Supports live packet-loss, latency, and corruption injection via console.
    """

    def __init__(self):
        self.sock     = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", SERVER_PORT))
        self.channels: Dict[str, List[tuple]] = {}
        self.running  = True

    def server_console(self):
        print("\nServer commands: LOSS <0-1>  LATENCY <ms>  CORRUPT <on|off>  STOP\n")
        while self.running:
            try:
                parts = input("[SERVER] > ").strip().split()
                if not parts:
                    continue
                cmd = parts[0].upper()
                if cmd == "LOSS" and len(parts) == 2:
                    NetConfig.LOSS_RATE = float(parts[1])
                    print(f"  Loss set → {NetConfig.LOSS_RATE}")
                elif cmd == "LATENCY" and len(parts) == 2:
                    NetConfig.LATENCY_MS = float(parts[1])
                    print(f"  Latency set → {NetConfig.LATENCY_MS} ms")
                # ── [NEW] Corruption toggle ────────────────────────
                elif cmd == "CORRUPT" and len(parts) == 2:
                    NetConfig.CORRUPT_ENABLED = parts[1].lower() == "on"
                    state = "ON — next DATA frame payload will be corrupted" if NetConfig.CORRUPT_ENABLED else "OFF"
                    print(f"  Corruption → {state}")
                elif cmd == "STOP":
                    self.running = False
                    self.sock.close()
                    break
                else:
                    NetConfig.show()
            except Exception:
                continue

    # ── [NEW] Corrupt helper — flips first byte of payload ──────
    @staticmethod
    def _corrupt_payload(raw: bytes) -> bytes:
        """
        Flips the first byte of the payload section (after the 10-byte header).
        This causes a CRC mismatch at the receiver, triggering NACK.
        The protocol itself is untouched — only the raw bytes are modified here.
        """
        hdr_size = struct.calcsize(ProtocolHandler.HEADER_FORMAT)
        if len(raw) > hdr_size:
            ba = bytearray(raw)
            ba[hdr_size] ^= 0xFF          # Flip all bits in first payload byte
            print("  [SIM] Payload corrupted → CRC mismatch will trigger NACK")
            return bytes(ba)
        return raw

    def start(self):
        print("=" * 60)
        print("  Secure Stop-and-Wait ARQ Relay Server")
        print(f"  Listening on 0.0.0.0:{SERVER_PORT}")
        print("=" * 60)
        threading.Thread(target=self.server_console, daemon=True).start()

        while self.running:
            try:
                raw, sender = self.sock.recvfrom(MAX_BUFFER)

                # ── Network impairment simulation ──────────────────
                if random.random() < NetConfig.LOSS_RATE:
                    print(f"  [SIM] Dropped packet from {sender}")
                    continue
                if NetConfig.LATENCY_MS > 0:
                    time.sleep(NetConfig.LATENCY_MS / 1000)

                # ── [NEW] Corruption simulation on DATA frames ─────
                # Parse a peek at frame type without full validation
                hdr_size = struct.calcsize(ProtocolHandler.HEADER_FORMAT)
                if NetConfig.CORRUPT_ENABLED and len(raw) > hdr_size:
                    try:
                        _, f_type_val, _, _ = struct.unpack(
                            ProtocolHandler.HEADER_FORMAT, raw[:hdr_size])
                        if f_type_val == FrameType.DATA.value:
                            raw = RelayServer._corrupt_payload(raw)
                            NetConfig.CORRUPT_ENABLED = False   # One-shot: auto-off after firing
                            print("  [SIM] Corruption auto-disabled (one-shot mode)")
                    except Exception:
                        pass

                channel_id, f_type, seq, payload = ProtocolHandler.parse_frame(raw)

                if f_type == FrameType.CREATE:
                    new_id = binascii.hexlify(os.urandom(3)).decode().upper()
                    self.channels[new_id] = [sender]
                    resp = ProtocolHandler.create_frame(
                        new_id, FrameType.CREATE, 0, b"CREATED")
                    self.sock.sendto(resp, sender)
                    print(f"  [+] Channel {new_id} created by {sender}")

                elif f_type == FrameType.JOIN:
                    if channel_id in self.channels and sender not in self.channels[channel_id]:
                        self.channels[channel_id].append(sender)
                    resp = ProtocolHandler.create_frame(
                        channel_id, FrameType.JOIN, 0, b"JOINED")
                    self.sock.sendto(resp, sender)
                    print(f"  [+] {sender} joined {channel_id}")

                elif f_type == FrameType.LEAVE:
                    if channel_id in self.channels and sender in self.channels[channel_id]:
                        self.channels[channel_id].remove(sender)
                    print(f"  [-] {sender} left {channel_id}")

                elif f_type in (FrameType.DATA, FrameType.ACK, FrameType.NACK):
                    # Relay to all other members of the channel
                    if channel_id in self.channels:
                        for target in self.channels[channel_id]:
                            if target != sender:
                                self.sock.sendto(raw, target)

            except Exception as e:
                if self.running:
                    print(f"  [SERVER ERROR] {e}")


# ================================================================
# STOP-AND-WAIT SENDER
# ================================================================
class SAWSender:
    """
    Stop-and-Wait sender.

    Protocol:
      1. Send frame with seq_no.
      2. Wait for ACK(seq_no) or NACK(seq_no).
         - ACK  → advance seq, return (success).
         - NACK → retransmit same frame immediately.
         - Timeout → retransmit same frame.
      3. Repeat for next message.

    Only ONE frame is ever in-flight at any time.
    [NEW] Gives up after MAX_RETRIES retransmissions.
    """

    def __init__(self, sock: socket.socket, server_address: tuple, channel_id_ref):
        self._sock       = sock
        self._server     = server_address
        self._ch         = channel_id_ref      # callable → current channel_id

        self._lock       = threading.Lock()
        self._seq        = 0                   # current sequence number
        self._ack_event  = threading.Event()   # set when ACK arrives
        self._nack_event = threading.Event()   # set when NACK arrives
        self._waiting    = False               # True while waiting for ACK/NACK

        # Stats
        self.frames_sent     = 0
        self.retransmissions = 0
        self.failed_frames   = 0              # [NEW] frames that hit MAX_RETRIES
        self.start_time      = time.time()

    def send(self, text: str):
        """
        Transmit one message using Stop-and-Wait.
        Blocks until ACK is received or MAX_RETRIES is exhausted.
        """
        payload = CryptoManager.encrypt(text, self._ch())
        seq     = self._seq

        frame = ProtocolHandler.create_frame(
            self._ch(), FrameType.DATA, seq, payload)

        with self._lock:
            self._waiting = True

        retry_count = 0   # [NEW] retransmission counter for this frame

        while True:
            # ── Transmit ──────────────────────────────────────────
            self._ack_event.clear()
            self._nack_event.clear()
            self._sock.sendto(frame, self._server)
            self.frames_sent += 1
            print(f"  [SAW] Sent Seq {seq}  (attempt {retry_count + 1}/{MAX_RETRIES + 1})")

            # ── Wait for ACK or NACK ──────────────────────────────
            deadline = time.time() + NetConfig.TIMEOUT
            got_ack  = False
            got_nack = False

            while time.time() < deadline:
                if self._ack_event.wait(timeout=0.05):
                    got_ack = True
                    break
                if self._nack_event.is_set():
                    got_nack = True
                    break

            if got_ack:
                # Success — advance sequence number
                self._seq = (seq + 1) % MAX_SEQ
                with self._lock:
                    self._waiting = False
                print(f"  [SAW] ACK({seq}) received → next seq = {self._seq}")
                return

            elif got_nack:
                self.retransmissions += 1
                retry_count += 1
                print(f"  [SAW] NACK({seq}) received → retransmitting Seq {seq}")

            else:
                self.retransmissions += 1
                retry_count += 1
                print(f"  [SAW] TIMEOUT → retransmitting Seq {seq}")

            # ── [NEW] Max retries guard ────────────────────────────
            if retry_count >= MAX_RETRIES:
                self.failed_frames += 1
                with self._lock:
                    self._waiting = False
                print(f"  [SAW] FAILED — Seq {seq} gave up after {MAX_RETRIES} retries.")
                print(f"  [SAW] Message dropped. Use STATS to review session performance.")
                # Advance seq so next message doesn't reuse the failed seq
                self._seq = (seq + 1) % MAX_SEQ
                return

    def notify_ack(self, seq: int):
        """Called by receiver thread when ACK arrives."""
        if seq == self._seq:
            self._ack_event.set()

    def notify_nack(self, seq: int):
        """Called by receiver thread when NACK arrives."""
        if seq == self._seq:
            self._nack_event.set()


# ================================================================
# STOP-AND-WAIT RECEIVER
# ================================================================
class SAWReceiver:
    """
    Stop-and-Wait receiver.

    - In-order frame  → decrypt, deliver, send ACK.
    - Duplicate frame → discard silently, re-send ACK (sender may not have received it).
    - Corrupt frame   → send NACK, wait for retransmit.
    """

    def __init__(self, sock: socket.socket, server_address: tuple, channel_id_ref):
        self._sock     = sock
        self._server   = server_address
        self._ch       = channel_id_ref
        self._expected = 0
        self.frames_received = 0

    @property
    def expected_seq(self):
        return self._expected

    def receive(self, seq: int, payload: bytes):
        """
        Process an incoming DATA frame.
        Returns decrypted message string if accepted, else None.
        """
        if seq == self._expected:
            # ── In-order: accept ──────────────────────────────────
            message = CryptoManager.decrypt(payload, self._ch())
            self._send_ack(seq)
            self._expected = (self._expected + 1) % MAX_SEQ
            self.frames_received += 1
            return message

        else:
            # ── Duplicate (already ACKed): re-send ACK ────────────
            print(f"  [SAW-RX] Duplicate Seq {seq} (expected {self._expected})"
                  f" → re-sending ACK({seq})")
            self._send_ack(seq)
            return None

    def send_nack(self):
        """Send NACK for the currently expected sequence (called on CRC error)."""
        print(f"  [SAW-RX] CRC error → NACK({self._expected})")
        nack = ProtocolHandler.create_frame(
            self._ch(), FrameType.NACK, self._expected, b"NACK")
        self._sock.sendto(nack, self._server)

    def _send_ack(self, seq: int):
        ack = ProtocolHandler.create_frame(
            self._ch(), FrameType.ACK, seq, b"ACK")
        self._sock.sendto(ack, self._server)
        print(f"  [SAW-RX] ACK({seq}) sent")


# ================================================================
# CLIENT
# ================================================================
class ARQClient:
    """
    Stop-and-Wait ARQ client.
    Integrates SAWSender + SAWReceiver, handles channel management,
    and provides an interactive CLI.
    """

    def __init__(self, server_ip: str):
        self.server_address = (server_ip, SERVER_PORT)
        self.sock           = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(1.0)
        self.channel_id     = "000000"
        self.running        = True

        self._sender   = SAWSender(self.sock, self.server_address, lambda: self.channel_id)
        self._receiver = SAWReceiver(self.sock, self.server_address, lambda: self.channel_id)

    # ── Background receiver thread ───────────────────────────────

    def _recv_loop(self):
        """
        Runs in daemon thread.
        Parses incoming frames and routes to sender/receiver handlers.
        Sends NACK automatically on CRC failure.
        """
        while self.running:
            try:
                raw, _ = self.sock.recvfrom(MAX_BUFFER)
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    print(f"  [RECV ERROR] {e}")
                continue

            # ── Parse frame; NACK on corruption ───────────────────
            try:
                channel_id, f_type, seq, payload = ProtocolHandler.parse_frame(raw)
            except ValueError as e:
                print(f"  [RECV] Corrupt frame ({e}) → sending NACK")
                self._receiver.send_nack()
                continue

            # ── Route by frame type ───────────────────────────────
            if f_type in (FrameType.CREATE, FrameType.JOIN):
                self.channel_id = channel_id
                print(f"\n  [SYSTEM] Connected to Channel {channel_id}\n")

            elif f_type == FrameType.ACK:
                self._sender.notify_ack(seq)

            elif f_type == FrameType.NACK:
                self._sender.notify_nack(seq)

            elif f_type == FrameType.DATA:
                message = self._receiver.receive(seq, payload)
                if message is not None:
                    print(f"\n  [{channel_id}] Msg: {message}\n")

    # ── Stats ────────────────────────────────────────────────────

    def show_stats(self):
        elapsed = time.time() - self._sender.start_time
        sent    = self._sender.frames_sent
        retx    = self._sender.retransmissions
        failed  = self._sender.failed_frames        # [NEW]
        total   = sent + retx
        eff     = (sent / total * 100) if total > 0 else 100.0
        print("\n===== SESSION STATS =====")
        print(f"  Elapsed         : {elapsed:.2f}s")
        print(f"  Frames Sent     : {sent}")
        print(f"  Retransmissions : {retx}")
        print(f"  Failed Frames   : {failed}  (hit MAX_RETRIES={MAX_RETRIES})")
        print(f"  Frames Received : {self._receiver.frames_received}")
        print(f"  ARQ Efficiency  : {eff:.2f}%")
        print("==========================\n")

    def inspect(self):
        print("\n--- INTERNAL STATE ---")
        print(f"  Channel ID      : {self.channel_id}")
        print(f"  Sender Seq      : {self._sender._seq}")
        print(f"  Expected Seq    : {self._receiver.expected_seq}")
        print(f"  Waiting for ACK : {self._sender._waiting}")
        NetConfig.show()

    # ── CLI ──────────────────────────────────────────────────────

    def ui(self):
        threading.Thread(target=self._recv_loop, daemon=True).start()

        print("\nCommands:")
        print("  CREATE                  — create new channel")
        print("  JOIN <channel_id>       — join existing channel")
        print("  LEAVE                   — leave current channel")
        print("  SEND <message>          — send message (Stop-and-Wait ARQ)")
        print("  SET LOSS <0-1>          — packet loss rate")
        print("  SET LATENCY <ms>        — one-way latency")
        print("  SET TIMEOUT <sec>       — retransmit timeout")
        print("  SET ENCRYPT <on|off>    — toggle encryption")
        print("  SHOW CONFIG             — display current configuration")
        print("  SHOW STATS / STATS      — display session statistics")   # [NEW alias]
        print("  INSPECT                 — display internal ARQ state\n")

        while self.running:
            try:
                raw_input = input(f"[{self.channel_id}] > ").strip()
                if not raw_input:
                    continue
                parts = raw_input.split(maxsplit=1)
                cmd   = parts[0].upper()
                arg   = parts[1] if len(parts) > 1 else ""

                if cmd == "CREATE":
                    frame = ProtocolHandler.create_frame(
                        "000000", FrameType.CREATE, 0, b"")
                    self.sock.sendto(frame, self.server_address)

                elif cmd == "JOIN":
                    frame = ProtocolHandler.create_frame(
                        arg.upper(), FrameType.JOIN, 0, b"")
                    self.sock.sendto(frame, self.server_address)

                elif cmd == "LEAVE":
                    frame = ProtocolHandler.create_frame(
                        self.channel_id, FrameType.LEAVE, 0, b"")
                    self.sock.sendto(frame, self.server_address)
                    self.channel_id = "000000"

                elif cmd == "SEND":
                    # ── [NEW] Input validation ─────────────────────
                    if not arg.strip():
                        print("  Error: Message cannot be empty.")
                    elif len(arg) > MAX_MSG_LEN:
                        print(f"  Error: Message too long ({len(arg)} chars). Max is {MAX_MSG_LEN}.")
                    elif self.channel_id == "000000":
                        print("  Join or create a channel first.")
                    elif self._sender._waiting:
                        print("  Still waiting for ACK on previous frame.")
                    else:
                        threading.Thread(
                            target=self._sender.send,
                            args=(arg,),
                            daemon=True
                        ).start()

                elif cmd == "SET":
                    sub = arg.split()
                    if len(sub) == 2:
                        key, val = sub[0].upper(), sub[1]
                        if key == "LOSS":
                            NetConfig.LOSS_RATE = float(val)
                        elif key == "LATENCY":
                            NetConfig.LATENCY_MS = float(val)
                        elif key == "TIMEOUT":
                            NetConfig.TIMEOUT = float(val)
                        elif key == "ENCRYPT":
                            NetConfig.ENCRYPTION_ENABLED = val.lower() == "on"
                        print("  [CONFIG UPDATED]")
                        NetConfig.show()
                    else:
                        print("  Usage: SET <LOSS|LATENCY|TIMEOUT|ENCRYPT> <value>")

                elif cmd == "SHOW":
                    sub = arg.upper()
                    if sub == "CONFIG":
                        NetConfig.show()
                    elif sub == "STATS":      # [NEW] alias
                        self.show_stats()
                    elif sub == "INSPECT":
                        self.inspect()
                    else:
                        print("  Usage: SHOW CONFIG | SHOW STATS | SHOW INSPECT")

                elif cmd == "STATS":          # original shorthand kept
                    self.show_stats()

                elif cmd == "INSPECT":
                    self.inspect()

                elif cmd == "EXIT":
                    self.running = False
                    self.sock.close()
                    break

                else:
                    print(f"  Unknown command: {cmd}. Type SHOW CONFIG for help.")

            except Exception as e:
                print(f"  [UI ERROR] {e}")


# ================================================================
# ENTRY POINT
# ================================================================
if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1].lower() == "server":
        RelayServer().start()
    else:
        print("\n  Secure Stop-and-Wait ARQ Client")
        ip = input("  Server IP (default 127.0.0.1): ").strip() or "127.0.0.1"
        ARQClient(ip).ui()
