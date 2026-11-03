<?php

declare(strict_types=1);

/**
 * Подпись сообщений WebMoney v2 (Ed25519).
 *
 * Файл — .kwm v2 в обычном base64 (после декодирования 136 байт), без XML.
 * Вместе с файлом передаются WMID и код доступа: по ним снимается Argon2id
 * и XChaCha20-Poly1305, внутри лежит сид подписи. Сообщение приводится к NFC
 * и подписывается как UTF-8 без BOM. Подпись — 128 шестнадцатеричных символов,
 * нижний регистр.
 */
final class Signer
{
    public const V2_SEED_SIZE = 32;
    public const V2_FILE_SIZE = 136;

    private const ARGON2_OPS = 2;
    private const ARGON2_MEMORY = 67108864;

    /** @var string|null */
    private $seed;

    /**
     * @param string $seed ровно 32 байта сида Ed25519
     */
    public function initialize(string $seed): void
    {
        $this->requireSodium();

        if (strlen($seed) !== self::V2_SEED_SIZE) {
            throw new InvalidArgumentException(sprintf(
                'Ed25519 seed must be exactly %d bytes long.',
                self::V2_SEED_SIZE
            ));
        }

        $this->clearSeed();
        // Своя копия: sodium_memzero не сможет затереть буфер, если на него
        // останется ссылка у вызывающего кода.
        $this->seed = substr($seed, 0);
    }

    /**
     * @param string $base64 .kwm v2 в base64
     * @param string $wmid   1–12 цифр, дописываются нули слева до 12
     * @param string $password код доступа к файлу ключей
     */
    public function initializeBase64(string $base64, string $wmid, string $password): void
    {
        $file = $this->decodeBase64($base64);

        try {
            $seed = $this->seedFromKeyFile($file, $wmid, $password);
        } finally {
            $this->wipe($file);
        }

        try {
            $this->initialize($seed);
        } finally {
            $this->wipe($seed);
        }
    }

    /**
     * Файл — текст в base64 (пробелы и перевод строки допустимы).
     * После декодирования — .kwm v2, 136 байт.
     */
    public function initializeFile(string $path, string $wmid, string $password): void
    {
        if (!is_file($path) || !is_readable($path)) {
            throw new InvalidArgumentException('Key file cannot be read: ' . $path);
        }

        $contents = file_get_contents($path);
        if ($contents === false) {
            throw new RuntimeException('Key file cannot be read: ' . $path);
        }

        $this->initializeBase64($contents, $wmid, $password);
    }

    public function isV2(): bool
    {
        return $this->seed !== null;
    }

    public function sign(string $message): string
    {
        if ($this->seed === null) {
            throw new RuntimeException('Signer must be initialized before it can be used.');
        }

        if (strpos($message, "\r") !== false) {
            throw new InvalidArgumentException("Message cannot contain of the following character: '\\r'.");
        }

        $this->requireSodium();

        if (preg_match('/[\x80-\xFF]/', $message) === 0) {
            // ASCII не меняется при NFC.
            $normalized = $message;
        } else {
            if (!class_exists(Normalizer::class)) {
                throw new RuntimeException('The intl extension is required to NFC-normalize non-ASCII messages.');
            }

            $normalized = Normalizer::normalize($message, Normalizer::FORM_C);
            if (!is_string($normalized)) {
                throw new InvalidArgumentException('Message is not valid UTF-8.');
            }
        }

        $keypair = sodium_crypto_sign_seed_keypair($this->seed);
        $secret = sodium_crypto_sign_secretkey($keypair);

        try {
            $signature = sodium_crypto_sign_detached($normalized, $secret);
        } finally {
            $this->wipe($secret);
            $this->wipe($keypair);
        }

        return sodium_bin2hex($signature);
    }

    public function dispose(): void
    {
        $this->clearSeed();
    }

    public function __destruct()
    {
        $this->clearSeed();
    }

    private function decodeBase64(string $base64): string
    {
        if (strncmp($base64, "\xEF\xBB\xBF", 3) === 0) {
            $base64 = substr($base64, 3);
        }

        $trimmed = ltrim($base64);
        if ($trimmed !== '' && $trimmed[0] === '<') {
            throw new InvalidArgumentException(
                'Key file must be the base64 of a .kwm v2, not XML.'
            );
        }

        $base64 = preg_replace('/\s+/', '', $base64);
        if (!is_string($base64) || $base64 === '') {
            throw new InvalidArgumentException('Base64 key file is empty.');
        }

        $file = base64_decode($base64, true);
        if ($file === false) {
            throw new InvalidArgumentException('Key file is not valid base64.');
        }

        return $file;
    }

    private function seedFromKeyFile(string $file, string $wmid, string $password): string
    {
        $this->requireSodium();

        if (strlen($file) < self::V2_FILE_SIZE) {
            throw new InvalidArgumentException(
                'Key file is shorter than 136 bytes. Expected a base64-encoded .kwm v2.'
            );
        }

        if ($this->readInt32($file, 20) !== 112 || $this->readInt32($file, 24) !== 2) {
            throw new InvalidArgumentException('Key file header is not v2.');
        }

        $wmid = $this->normalizeWmid($wmid);
        $password = $this->toAscii($password);

        try {
            $fileKey = sodium_crypto_pwhash(
                self::V2_SEED_SIZE,
                $password,
                substr($file, 4, 16),
                self::ARGON2_OPS,
                self::ARGON2_MEMORY,
                SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13
            );
        } finally {
            $this->wipe($password);
        }

        try {
            $plain = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
                substr($file, 52, 84),
                substr($file, 0, 52) . $wmid,
                substr($file, 28, 24),
                $fileKey
            );
        } finally {
            $this->wipe($fileKey);
        }

        if ($plain === false) {
            throw new RuntimeException('Wrong WMID or password.');
        }

        try {
            if (strlen($plain) < 68
                || $this->readUint16($plain, 0) !== self::V2_SEED_SIZE
                || $this->readUint16($plain, 34) !== self::V2_SEED_SIZE) {
                throw new RuntimeException('Decrypted key file has unexpected key lengths.');
            }

            return substr($plain, 2, self::V2_SEED_SIZE);
        } finally {
            $this->wipe($plain);
        }
    }

    private function normalizeWmid(string $wmid): string
    {
        $wmid = trim($wmid);
        if (!preg_match('/^\d{1,12}$/', $wmid)) {
            throw new InvalidArgumentException('WMID must be 1 to 12 digits.');
        }

        return str_pad($wmid, 12, '0', STR_PAD_LEFT);
    }

    private function toAscii(string $text): string
    {
        if ($text === '') {
            throw new InvalidArgumentException('Password is empty.');
        }

        $chars = preg_split('//u', $text, -1, PREG_SPLIT_NO_EMPTY);
        if ($chars === false) {
            return preg_replace('/[\x80-\xFF]/', '?', $text);
        }

        $ascii = '';
        foreach ($chars as $char) {
            $ascii .= strlen($char) === 1 ? $char : '?';
        }

        return $ascii;
    }

    private function readUint16(string $data, int $offset): int
    {
        $value = unpack('v', substr($data, $offset, 2));

        return $value[1];
    }

    private function readInt32(string $data, int $offset): int
    {
        $value = unpack('V', substr($data, $offset, 4));

        return $value[1];
    }

    private function clearSeed(): void
    {
        if ($this->seed === null) {
            return;
        }

        $seed = $this->seed;
        $this->seed = null;
        $this->wipe($seed);
    }

    private function wipe(string &$buffer): void
    {
        if (!function_exists('sodium_memzero')) {
            return;
        }

        try {
            sodium_memzero($buffer);
        } catch (SodiumException $exception) {
            // Буфер разделяется с другим значением — ссылку всё равно отпускаем.
        }
    }

    private function requireSodium(): void
    {
        if (!extension_loaded('sodium')) {
            throw new RuntimeException('The sodium extension is required for Ed25519.');
        }
    }
}
