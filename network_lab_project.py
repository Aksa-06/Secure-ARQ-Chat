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
MAX_BUFFER_SIZE = 4096


class NetConfig:
    LOSS_RATE = 0.0
    LATENCY_MS = 0.0
    TIMEOUT = 2.0
    ENCRYPTION_ENABLED = True

    @staticmethod
    def show():
        print("\n--- CURRENT CONFIGURATION ---")
        print(f"Loss Rate        : {NetConfig.LOSS_RATE}")
        print(f"Latency (ms)     : {NetConfig.LATENCY_MS}")
        print(f"Timeout (sec)    : {NetConfig.TIMEOUT}")
        print(f"Encryption       : {'ON' if NetConfig.ENCRYPTION_ENABLED else 'OFF'}")
        print("------------------------------\n")


# ================================================================
# APPLICATION LAYER: END-TO-END ENCRYPTION (XOR)
# ================================================================
class CryptoManager:
    @staticmethod
    def _derive_key(channel_id: str) -> bytes:
        return binascii.hexlify(channel_id.encode())[:16]

    @staticmethod
    def encrypt(plaintext: str, channel_id: str) -> bytes:
        if not NetConfig.ENCRYPTION_ENABLED:
            return plaintext.encode()

        key = CryptoManager._derive_key(channel_id)
        return bytes(
            ord(plaintext[i]) ^ key[i % len(key)]
            for i in range(len(plaintext))
        )

    @staticmethod
    def decrypt(ciphertext: bytes, channel_id: str) -> str:
        if not NetConfig.ENCRYPTION_ENABLED:
            return ciphertext.decode(errors="ignore")

        key = CryptoManager._derive_key(channel_id)
        decrypted = bytes(
            ciphertext[i] ^ key[i % len(key)]
            for i in range(len(ciphertext))
        )
        return decrypted.decode(errors="ignore")


# ================================================================
# DATA LINK LAYER: FRAMING + CRC
# ================================================================
class FrameType(Enum):
    DATA = 0
    ACK = 1
    JOIN = 2
    CREATE = 3
    LEAVE = 4


class ProtocolHandler:
    HEADER_FORMAT = "!3sBIH"

    @staticmethod
    def compute_crc(data: bytes) -> int:
        return binascii.crc_hqx(data, 0xFFFF)

    @staticmethod
    def create_frame(channel_id: str,
                     frame_type: FrameType,
                     seq_no: int,
                     payload: bytes) -> bytes:

        channel_id = channel_id.strip().upper().zfill(6)
        channel_bytes = binascii.unhexlify(channel_id)
        crc = ProtocolHandler.compute_crc(payload)

        header = struct.pack(
            ProtocolHandler.HEADER_FORMAT,
            channel_bytes,
            frame_type.value,
            seq_no,
            crc
        )

        return header + payload

    @staticmethod
    def parse_frame(frame: bytes) -> Tuple[str, FrameType, int, bytes]:
        header_size = struct.calcsize(ProtocolHandler.HEADER_FORMAT)

        if len(frame) < header_size:
            raise ValueError("Frame too short")

        header = frame[:header_size]
        payload = frame[header_size:]

        channel_bytes, f_type, seq_no, recv_crc = struct.unpack(
            ProtocolHandler.HEADER_FORMAT,
            header
        )

        actual_crc = ProtocolHandler.compute_crc(payload)
        if actual_crc != recv_crc:
            raise ValueError("CRC mismatch")

        channel_id = binascii.hexlify(channel_bytes).decode().upper()

        return channel_id, FrameType(f_type), seq_no, payload


# ================================================================
# RELAY SERVER
# ================================================================
class RelayServer:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", SERVER_PORT))
        self.channels: Dict[str, List[tuple]] = {}
        self.running = True

    def server_console(self):
        while self.running:
            try:
                cmd = input("[SERVER CONFIG] > ").strip()
                parts = cmd.split()

                if len(parts) == 2 and parts[0].upper() == "LOSS":
                    NetConfig.LOSS_RATE = float(parts[1])
                    print(f"[SERVER] Loss set to {NetConfig.LOSS_RATE}")

                elif len(parts) == 2 and parts[0].upper() == "LATENCY":
                    NetConfig.LATENCY_MS = float(parts[1])
                    print(f"[SERVER] Latency set to {NetConfig.LATENCY_MS}")

                elif parts[0].upper() == "STOP":
                    print("[SERVER] Shutting down...")
                    self.running = False
                    self.sock.close()
                    break

            except:
                continue

    def start(self):
        print("=" * 60)
        print(" Secure ARQ Relay Server Running")
        print(f" Listening on 0.0.0.0:{SERVER_PORT}")
        print("=" * 60)

        threading.Thread(target=self.server_console, daemon=True).start()

        while self.running:
            try:
                frame, sender = self.sock.recvfrom(MAX_BUFFER_SIZE)

                if random.random() < NetConfig.LOSS_RATE:
                    print(f"[SIMULATION] Dropped packet from {sender}")
                    continue

                if NetConfig.LATENCY_MS > 0:
                    time.sleep(NetConfig.LATENCY_MS / 1000)

                channel_id, f_type, seq, payload = ProtocolHandler.parse_frame(frame)

                if f_type == FrameType.CREATE:
                    new_id = binascii.hexlify(os.urandom(3)).decode().upper()
                    self.channels[new_id] = [sender]

                    response = ProtocolHandler.create_frame(
                        new_id, FrameType.CREATE, 0, b"CREATED"
                    )
                    self.sock.sendto(response, sender)

                    print(f"[SERVER] Channel {new_id} created by {sender}")

                elif f_type == FrameType.JOIN:
                    if channel_id in self.channels:
                        if sender not in self.channels[channel_id]:
                            self.channels[channel_id].append(sender)

                        response = ProtocolHandler.create_frame(
                            channel_id, FrameType.JOIN, 0, b"JOINED"
                        )
                        self.sock.sendto(response, sender)

                        print(f"[SERVER] {sender} joined {channel_id}")

                elif f_type == FrameType.LEAVE:
                    if channel_id in self.channels:
                        self.channels[channel_id].remove(sender)
                        print(f"[SERVER] {sender} left {channel_id}")

                elif f_type in (FrameType.DATA, FrameType.ACK):
                    if channel_id in self.channels:
                        for target in self.channels[channel_id]:
                            if target != sender:
                                self.sock.sendto(frame, target)

            except Exception as e:
                if self.running:
                    print("[SERVER ERROR]", e)


# ================================================================
# CLIENT (Stop-and-Wait ARQ)
# ================================================================
class ARQClient:
    def __init__(self, server_ip: str):
        self.server_address = (server_ip, SERVER_PORT)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(1.0)
        self.channel_id = "000000"
        self.send_seq = 0
        self.expected_seq = 0

        self.ack_event = threading.Event()
        self.last_ack = -1
        self.running = True

        # Stats
        self.frames_sent = 0
        self.retransmissions = 0
        self.frames_received = 0
        self.start_time = time.time()

    def receiver(self):
        while self.running:
            try:
                frame, _ = self.sock.recvfrom(MAX_BUFFER_SIZE)
                channel_id, f_type, seq, payload = ProtocolHandler.parse_frame(frame)

                if f_type in (FrameType.CREATE, FrameType.JOIN):
                    self.channel_id = channel_id
                    print(f"\n[SYSTEM] Connected to Channel {channel_id}")

                elif f_type == FrameType.ACK:
                    self.last_ack = seq
                    self.ack_event.set()

                elif f_type == FrameType.DATA:
                    if seq == self.expected_seq:
                        message = CryptoManager.decrypt(payload, self.channel_id)
                        print(f"\n[{self.channel_id}] Message: {message}")

                        ack = ProtocolHandler.create_frame(
                            self.channel_id, FrameType.ACK, seq, b"ACK"
                        )
                        self.sock.sendto(ack, self.server_address)

                        self.expected_seq += 1
                        self.frames_received += 1

            except socket.timeout:
                continue

            except Exception as e:
                if self.running:
                    print("[CLIENT ERROR]", e)

    def send_message(self, text: str):
        payload = CryptoManager.encrypt(text, self.channel_id)
        seq = self.send_seq

        frame = ProtocolHandler.create_frame(
            self.channel_id, FrameType.DATA, seq, payload
        )

        while True:
            self.ack_event.clear()
            self.sock.sendto(frame, self.server_address)
            self.frames_sent += 1
            print(f"[SEND] Seq {seq}")

            if self.ack_event.wait(NetConfig.TIMEOUT):
                if self.last_ack >= seq:
                    self.send_seq += 1
                    return

            self.retransmissions += 1
            print(f"[TIMEOUT] Retransmitting Seq {seq}")

    def show_stats(self):
        elapsed = time.time() - self.start_time
        total = self.frames_sent + self.retransmissions
        efficiency = (self.frames_sent / total * 100) if total > 0 else 100

        print("\n===== SESSION STATS =====")
        print(f"Elapsed Time      : {elapsed:.2f}s")
        print(f"Frames Sent       : {self.frames_sent}")
        print(f"Retransmissions   : {self.retransmissions}")
        print(f"Frames Received   : {self.frames_received}")
        print(f"ARQ Efficiency    : {efficiency:.2f}%")
        print("==========================\n")

    def inspect(self):
        print("\n--- INTERNAL STATE ---")
        print(f"Channel ID      : {self.channel_id}")
        print(f"Send Seq        : {self.send_seq}")
        print(f"Expected Seq    : {self.expected_seq}")
        print(f"Last ACK        : {self.last_ack}")
        NetConfig.show()

    def ui(self):
        threading.Thread(target=self.receiver, daemon=True).start()

        print("\nCommands:")
        print(" CREATE")
        print(" JOIN <ChannelID>")
        print(" LEAVE")
        print(" SEND <message>")
        print(" SET LOSS <0-1>")
        print(" SET LATENCY <ms>")
        print(" SET TIMEOUT <sec>")
        print(" SET ENCRYPT <on/off>")
        print(" SHOW CONFIG")
        print(" STATS")
        print(" INSPECT")
        print(" EXIT\n")

        while self.running:
            try:
                user_input = input(f"[{self.channel_id}] > ").strip()
                if not user_input:
                    continue

                parts = user_input.split(maxsplit=1)
                cmd = parts[0].upper()
                arg = parts[1] if len(parts) > 1 else ""

                if cmd == "CREATE":
                    print("[DEBUG] Sending CREATE")
                    frame = ProtocolHandler.create_frame(
                        "000000", FrameType.CREATE, 0, b""
                    )
                    self.sock.sendto(frame, self.server_address)

                elif cmd == "JOIN":
                    frame = ProtocolHandler.create_frame(
                        arg.upper(), FrameType.JOIN, 0, b""
                    )
                    self.sock.sendto(frame, self.server_address)

                elif cmd == "LEAVE":
                    frame = ProtocolHandler.create_frame(
                        self.channel_id, FrameType.LEAVE, 0, b""
                    )
                    self.sock.sendto(frame, self.server_address)
                    self.channel_id = "000000"

                elif cmd == "SEND":
                    if self.channel_id == "000000":
                        print("Join or create a channel first.")
                    else:
                        self.send_message(arg)

                elif cmd == "SET":
                    sub = arg.split()
                    if len(sub) == 2:
                        key = sub[0].upper()
                        val = sub[1]

                        if key == "LOSS":
                            NetConfig.LOSS_RATE = float(val)
                        elif key == "LATENCY":
                            NetConfig.LATENCY_MS = float(val)
                        elif key == "TIMEOUT":
                            NetConfig.TIMEOUT = float(val)
                        elif key == "ENCRYPT":
                            NetConfig.ENCRYPTION_ENABLED = val.lower() == "on"

                        print("[CONFIG UPDATED]")
                        NetConfig.show()

                elif cmd == "SHOW" and arg.upper() == "CONFIG":
                    NetConfig.show()

                elif cmd == "STATS":
                    self.show_stats()

                elif cmd == "INSPECT":
                    self.inspect()

                elif cmd == "EXIT":
                    self.running = False
                    self.sock.close()
                    break

            except Exception as e:
                print(f"[UI ERROR] {e}")


# ================================================================
# ENTRY POINT
# ================================================================
if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1].lower() == "server":
        RelayServer().start()
    else:
        print("\nSecure ARQ Client")
        server_ip = input("Enter Server IP (default 127.0.0.1): ").strip()
        if not server_ip:
            server_ip = "127.0.0.1"

        ARQClient(server_ip).ui()
