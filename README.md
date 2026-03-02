# Secure Channel-Based Communication using Stop-and-Wait ARQ

## Overview

This project implements a secure, command-line–based communication system that demonstrates core Computer Networks concepts.

Clients can create or join logical communication channels identified by a 6-digit hexadecimal Channel ID. Messages exchanged within a channel are end-to-end encrypted, and reliable delivery is ensured using a custom Stop-and-Wait ARQ protocol implemented over UDP.

The server acts purely as a relay and never decrypts message payloads.

---

## Concepts Demonstrated

- OSI Layered Architecture
- UDP-based communication
- Frame-based transmission
- CRC error detection
- Stop-and-Wait ARQ (retransmission & timeout)
- Logical channel addressing (24-bit ID)
- End-to-End Encryption
- Basic firewall configuration for controlled port exposure

---

## How It Works

Each message is transmitted as a frame:

ChannelID | Type | Sequence Number | Payload | CRC

- Payload is encrypted at the sender.
- CRC is computed for error detection.
- Stop-and-Wait ARQ ensures reliable delivery.
- The server relays frames to clients in the same channel.

---

## How to Run

### 1. Start the Server (on server machine)

python filename.py server

> Make sure UDP port 5000 is allowed in Windows Firewall (Private profile).

### 2. Start a Client

python network_lab_project.py

> When prompted, enter the Server IP address.

### 3. Commands

- CREATE → Create a new channel
- JOIN <ChannelID> → Join an existing channel
- SEND <message> → Send message
- SET LOSS <0-1> → Simulate packet loss
- EXIT → Exit client

---

## Notes

- Only UDP port 5000 needs to be enabled on the server.
- Both systems must be on the same network.
- Firewall rule can be disabled when not testing.
