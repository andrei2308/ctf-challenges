# Chimera Void — Network Writeup

**Category:** Network  
**Flag:** `CTF{CONGRATS_WINNERS}`

## Overview

We are given a `.pcap` capture file (`chimera_void.pcap`). The goal is to find the hidden flag within the network traffic.

## Solution

### Step 1 — Analyze the PCAP in Wireshark

Opening the file in Wireshark reveals a massive amount of network traffic. Most of it is deliberate **noise** — random data injected to obfuscate the real communication and hinder automated analysis.

By filtering out the noise traffic, we discover an alternative **TCP stream** that stands out. Following this stream reveals it is transmitting a `.gcode` file.

### Step 2 — Extract the G-code file

We extract the `.gcode` data from the TCP stream using Wireshark's "Follow TCP Stream" → "Save As" functionality, producing `chimera_test.gcode`.

### Step 3 — Understand G-code

G-code is a language used to control CNC machines and **3D printers**. It describes motion paths using commands like:

- `G0 X... Y...` — rapid travel move (non-printing)
- `G1 X... Y...` — linear move (printing/extrusion)

The key insight is that G-code can encode **images** — the print head traces out shapes that form visible patterns.

### Step 4 — Render the G-code

The rendered image spells out the flag.

Pasting the `.gcode` into an online G-code interpreter/viewer renders the image from which the flag can be read.

## Flag

```
CTF{CONGRATS_WINNERS}
```
