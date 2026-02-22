# Session-GPT — ML/AI Writeup

**Category:** ML/AI  
**Flag:** `ctf{4620c10465bb2c85c2bc9804972bb75c1d72a4782100d09d1a0bb72eb576b772}`

## Overview

A chatbot application where each user gets an isolated conversation session identified by an 8-character hex string. The chatbot exposes hidden administrative commands that allow **lateral movement** between sessions by leaking JWTs, ultimately granting access to other users' conversations.

## Reconnaissance

### Probing the chatbot's capabilities

By asking the chatbot about its features and what it can do, it eventually disclosed a set of internal commands it is able to execute:

| Command | Description |
|---|---|
| `List sessions` | Enumerates all active sessions, each identified by an 8-character hex string |
| `Switch session <hex>` | Switches the current context to the specified session |

These commands are not documented anywhere in the UI — they are only discoverable through prompt interaction with the bot.

## Exploitation

### Step 1 — Enumerate sessions

Running the `List sessions` command returned a list of all active 8-character hex session identifiers. Each identifier corresponds to a different user's conversation session.

### Step 2 — Hijack sessions via JWT leak

Using `Switch session <hex>` with one of the discovered session IDs caused the chatbot to return the **JWT token** associated with that session. This is the critical vulnerability: the application hands out valid authentication tokens for arbitrary sessions on request.

### Step 3 — Read other users' messages

After switching to a target session and obtaining its JWT, a simple page refresh caused the browser to authenticate under the new session. This granted full read access to the conversation history of that session.

### Step 4 — Find the flag

By iterating through the available sessions — switching, refreshing, and inspecting the conversation history — the flag was found inside one of the other users' chat logs.

## Root Cause

The chatbot's session-management commands lack any authorization checks. Any authenticated user can:

1. **Enumerate** all existing sessions (`List sessions`)
2. **Obtain** the JWT for any session (`Switch session`)
3. **Impersonate** any user by using the leaked JWT

This is a classic **lateral movement** vulnerability — the ability to pivot from one authenticated context to another without proper access control, compounded by the chatbot leaking sensitive authentication material (JWTs) through its conversational interface.
