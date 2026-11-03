# WebMoney Signer (PHP)

Signs WebMoney messages with a v2 key (Ed25519). The signer takes a `.kwm` v2 key file encoded as base64, your WMID and the key file password, and returns a 128-character lowercase hex signature.

## Requirements

- PHP 7.4 or newer
- `sodium` extension (Ed25519, Argon2id, XChaCha20-Poly1305)
- `intl` extension (needed only to sign messages with non-ASCII characters)

Check that both extensions are enabled:

```bash
php -m | grep -E 'sodium|intl'
```

## Step 1. Convert the key file to base64

The signer does not read the binary `.kwm` file directly. Convert it to a base64 string first. A valid v2 key file is exactly 136 bytes before encoding.

**Linux:**

```bash
base64 -w0 keys.kwm > keys.b64
```

**macOS:**

```bash
base64 -i keys.kwm -o keys.b64
```

**Windows (PowerShell):**

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("keys.kwm")) | Set-Content -NoNewline keys.b64
```

**Any OS, using PHP:**

```bash
php -r 'echo base64_encode(file_get_contents("keys.kwm"));' > keys.b64
```

Check the result: the decoded file must be 136 bytes.

```bash
base64 -d keys.b64 | wc -c
# 136
```

Line breaks and spaces inside the base64 text are allowed. An XML key file (old format) is not supported.

## Step 2. Sign a message in the console

```bash
php sign.php <keys.b64 | base64 string> <WMID> <password> <message>
```

The first argument is either the path to the base64 file or the base64 string itself.

**Using the base64 file:**

```bash
php sign.php keys.b64 123456789012 'MyKeyPassword' 'Hello, WebMoney'
```

**Using the base64 string directly:**

```bash
php sign.php "$(cat keys.b64)" 123456789012 'MyKeyPassword' 'Hello, WebMoney'
```

Output is the signature, 128 hex characters:

```text
3f9a...e01c
```

If the WMID or password is wrong, the script fails with `Wrong WMID or password.`

Notes:

- WMID is 1 to 12 digits; shorter values are padded with leading zeros.
- Use single quotes around the password and message so the shell does not expand `$`, `!` and similar characters.
- The message must not contain `\r`. Non-ASCII messages are normalized to Unicode NFC and signed as UTF-8.
- Arguments passed on the command line are saved in shell history. To avoid storing the password, prefix the command with a space (in bash with `HISTCONTROL=ignorespace`) or read it into a variable:

  ```bash
  read -rs WM_PASSWORD
  php sign.php keys.b64 123456789012 "$WM_PASSWORD" 'Hello, WebMoney'
  ```

## Using the signer from PHP code

```php
<?php

require __DIR__ . '/src/Signer.php';

$signer = new Signer();

// From a base64 file:
$signer->initializeFile(__DIR__ . '/keys.b64', '123456789012', 'MyKeyPassword');

// Or from a base64 string:
// $signer->initializeBase64($base64, '123456789012', 'MyKeyPassword');

$signature = $signer->sign('Hello, WebMoney');
echo $signature, PHP_EOL;

// Wipe the key from memory when done.
$signer->dispose();
```

With Composer, the class is autoloaded via `classmap`, so `require 'vendor/autoload.php';` is enough.

## Running tests

```bash
php tests/SignerV2Test.php
```
