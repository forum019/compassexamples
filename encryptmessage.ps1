$pub = [IO.File]::ReadAllBytes(".\public.key")
$rsaPub = [Security.Cryptography.RSA]::Create()
$rsaPub.ImportRSAPublicKey($pub, [ref]0) | Out-Null

$message = "Meet at the gym at 6pm."
$bytes = [Text.Encoding]::UTF8.GetBytes($message)

# RSA is for small data; OAEP padding is modern/safe
$cipher = $rsaPub.Encrypt($bytes, [Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)

[IO.File]::WriteAllBytes(".\message.rsa", $cipher)
Write-Host "Encrypted message saved to message.rsa"
