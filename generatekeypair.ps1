# Generate an RSA keypair
$rsa = [Security.Cryptography.RSA]::Create(2048)

# Export keys
$publicKey  = $rsa.ExportRSAPublicKey()
$privateKey = $rsa.ExportRSAPrivateKey()

[IO.File]::WriteAllBytes(".\public.key",  $publicKey)
[IO.File]::WriteAllBytes(".\private.key", $privateKey)

Write-Host "Keys saved: public.key (shareable) and private.key (KEEP SECRET)"
