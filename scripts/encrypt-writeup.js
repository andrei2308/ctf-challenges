#!/usr/bin/env node
// Encrypts a plaintext HTML fragment for a password-gated writeup page.
//
// Uses Node's built-in WebCrypto (the same standardized SubtleCrypto API
// browsers implement) so the produced ciphertext is guaranteed compatible
// with the client-side decryption code in the protected page template,
// without adding any third-party dependency.
//
// Usage:
//   node scripts/encrypt-writeup.js <plaintext-file> <output.enc.json> <password>
//
// The plaintext file is never written anywhere in the repo. Keep your own
// copy somewhere safe (password manager / encrypted vault) if you want to
// edit the content later -- there is no way to recover it from the
// ciphertext without the password.

const fs = require("fs");
const { webcrypto } = require("crypto");
const { subtle } = webcrypto;

const PBKDF2_ITERATIONS = 600000;

async function main() {
  const [, , inputPath, outputPath, password] = process.argv;
  if (!inputPath || !outputPath || !password) {
    console.error(
      "Usage: node scripts/encrypt-writeup.js <plaintext-file> <output.enc.json> <password>"
    );
    process.exit(1);
  }

  const plaintext = fs.readFileSync(inputPath, "utf8");
  const enc = new TextEncoder();

  const salt = webcrypto.getRandomValues(new Uint8Array(16));
  const iv = webcrypto.getRandomValues(new Uint8Array(12));

  const keyMaterial = await subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  const key = await subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"]
  );

  const ciphertext = await subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    enc.encode(plaintext)
  );

  const out = {
    v: 1,
    kdf: "PBKDF2-SHA256",
    iterations: PBKDF2_ITERATIONS,
    salt: Buffer.from(salt).toString("base64"),
    iv: Buffer.from(iv).toString("base64"),
    ciphertext: Buffer.from(ciphertext).toString("base64"),
  };

  fs.writeFileSync(outputPath, JSON.stringify(out));
  console.log(`wrote ${outputPath} (${out.ciphertext.length} b64 chars of ciphertext)`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
