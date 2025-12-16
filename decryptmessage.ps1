$priv = [IO.File]::ReadAllBytes(".\private.key")
$rsaPriv = [Security.Cryptography.RSA]::Create()
$rsaPriv.ImportRSAPrivateKey($priv, [ref]0) | Out-Null

$cipher = [IO.File]::ReadAllBytes(".\message.rsa")
$plain = $rsaPriv.Decrypt($cipher, [Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)

[Text.Encoding]::UTF8.GetString($plain)
