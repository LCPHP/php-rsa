<?php
/**
 * Rsa 加密解密示例
 * author ：niklaslu <332553882@qq.com>
 */

require_once 'vendor/autoload.php';

$Rsa = new \niklaslu\Rsa();

$publicKey = $Rsa->getPublicKeyStr();
echo $publicKey;
echo "<br>";

$pravateKey = $Rsa->getPrivateKeyStr();

echo $pravateKey;
echo "<br>";

$data = 'data1';

// 通过私钥加密
$enc = $Rsa->encryptByPrivate($data);
echo $enc;
echo "<br>";

// 通过公钥解密
$dec = $Rsa->decryptByPublic($enc);
echo $dec;
echo "<br>";


$data = 'data2';

// 通过公钥加密
$enc = $Rsa->encryptByPublic($data);
echo $enc;
echo "<br>";

// 通过私钥解密
$dec = $Rsa->decryptByPrivate($enc);
echo $dec;
echo "<br>";