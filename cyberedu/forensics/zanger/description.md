# Challenge: zanger

## Description
One communications protocol over certain ports to rule them all.

**Flag format:** `ctf{sha256}`

**Goal:** In this challenge you receive a capture dump and your goal is to find the attacker techniques used to leak the flag.

## Initial Analysis

We are provided with a pcap file that seems to only use UDP and TCP but send no data. We have some hints about the ports in the description so we will try to look at them.

## Investigation

After filtering by TCP we see that we have less than UDP so maybe that is where we need to look. I looked manually at the first destination ports from TCP packets and found some interesting **1337 port** from which I knew I was on the good path.

## Solution Method

After many attempts I figured it out. Each destination port should be treated as a **nybble** (4-bit value) and then reconstructed as hex - the flag will be revealed.

### Technique Explanation

The attacker used **port numbers as a covert channel** to exfiltrate data. By encoding each nybble of the flag as a destination port number in the TCP packets, the flag could be transmitted without sending any actual payload data.

## Exploit

The exploit is in this repository.