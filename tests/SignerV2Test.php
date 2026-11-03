<?php

declare(strict_types=1);

require dirname(__DIR__) . '/src/Signer.php';

function check(bool $condition, string $name): void
{
    if (!$condition) {
        fwrite(STDERR, "FAIL {$name}\n");
        exit(1);
    }

    fwrite(STDOUT, "ok {$name}\n");
}

function expect(string $class, callable $fn, string $name): void
{
    try {
        $fn();
    } catch (Throwable $exception) {
        check($exception instanceof $class, $name . ' (' . get_class($exception) . ': ' . $exception->getMessage() . ')');
        return;
    }

    check(false, $name . ' (no exception)');
}

$seed = hex2bin('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60');
$emptySignature = 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b';

$signer = new Signer();
$signer->initialize($seed);
check($signer->isV2(), 'is v2');
check($signer->sign('') === $emptySignature, 'rfc 8032 test 1 empty message');

$wmid = '1';
$password = 'access-code';
$kwm = buildV2Kwm($seed, '000000000001', $password, random_bytes(32));
$signer->initializeBase64(base64_encode($kwm), $wmid, $password);
check($signer->sign('') === $emptySignature, 'kwm base64 unlocks the same seed');

$path = tempnam(sys_get_temp_dir(), 'wmkwm');
file_put_contents($path, "\xEF\xBB\xBF" . chunk_split(base64_encode($kwm), 16, "\r\n"));
$signer->initializeFile($path, $wmid, $password);
check($signer->sign('') === $emptySignature, 'base64 kwm file with bom and line breaks');
unlink($path);

expect(RuntimeException::class, static function () use ($signer, $kwm, $wmid): void {
    $signer->initializeBase64(base64_encode($kwm), $wmid, 'wrong-password');
}, 'wrong password rejected');

$oneByte = hex2bin('4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb');
$signer->initialize($oneByte);
check(
    $signer->sign('r') === '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00',
    'rfc 8032 test 2'
);

$stableSeed = hex2bin('c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7');
$signer->initialize($stableSeed);
$first = $signer->sign('test');
$second = $signer->sign('test');
check(strlen($first) === 128 && $first === strtolower($first) && $first === $second, '128 lowercase hex, deterministic');

$composed = "стро\u{0439}ка";
$decomposed = "стро\u{0438}\u{0306}ка";
check($composed !== $decomposed, 'composed and decomposed differ as strings');
check($signer->sign($composed) === $signer->sign($decomposed), 'nfc folds cyrillic short i');

$greeting = $signer->sign('привет');
$secret = sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair($stableSeed));
$plain = sodium_bin2hex(sodium_crypto_sign_detached('привет', $secret));
$withBom = sodium_bin2hex(sodium_crypto_sign_detached("\xEF\xBB\xBF" . 'привет', $secret));
sodium_memzero($secret);
check($greeting === $plain, 'message bytes are utf-8');
check($greeting !== $withBom, 'message has no bom');

expect(InvalidArgumentException::class, static function () use ($signer): void {
    $signer->sign("a\r\nb");
}, 'carriage return rejected');

expect(InvalidArgumentException::class, static function (): void {
    (new Signer())->initialize(random_bytes(31));
}, 'short seed rejected');

expect(InvalidArgumentException::class, static function (): void {
    (new Signer())->initializeBase64('<Ed25519KeyValue><Seed>AAAA</Seed></Ed25519KeyValue>', '1', 'password');
}, 'xml rejected');

expect(RuntimeException::class, static function (): void {
    (new Signer())->sign('test');
}, 'sign before initialize');

$signer->dispose();
check(!$signer->isV2(), 'disposed');
expect(RuntimeException::class, static function () use ($signer): void {
    $signer->sign('test');
}, 'sign after dispose');

$signer->initialize($seed);
check($signer->sign('') === $emptySignature, 'initialize after dispose');

fwrite(STDOUT, "all checks passed\n");

function buildV2Kwm(string $seed, string $wmid, string $password, string $exchange): string
{
    $salt = random_bytes(16);
    $nonce = random_bytes(24);
    $header = pack('v', 0x0081) . pack('v', 0) . $salt . pack('V', 112) . pack('V', 2) . $nonce;
    $plain = pack('v', 32) . $seed . pack('v', 32) . $exchange;
    $key = sodium_crypto_pwhash(32, $password, $salt, 2, 67108864, SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13);

    try {
        $cipher = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($plain, $header . $wmid, $nonce, $key);
    } finally {
        sodium_memzero($key);
        sodium_memzero($plain);
    }

    return $header . $cipher;
}
