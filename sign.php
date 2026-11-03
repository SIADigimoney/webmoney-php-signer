<?php

declare(strict_types=1);

require __DIR__ . '/src/Signer.php';

if ($argc < 5) {
    fwrite(STDERR, "Использование: php sign.php <файл.b64|base64> <WMID> <пароль> <сообщение>\n");
    fwrite(STDERR, "Первый аргумент — путь к .kwm v2 в base64 или сама строка base64.\n");
    fwrite(STDERR, "Пароль — код доступа к файлу ключей.\n");
    exit(1);
}

$signer = new Signer();
if (is_file($argv[1]) && is_readable($argv[1])) {
    $signer->initializeFile($argv[1], $argv[2], $argv[3]);
} else {
    $signer->initializeBase64($argv[1], $argv[2], $argv[3]);
}
echo $signer->sign($argv[4]), PHP_EOL;
$signer->dispose();
