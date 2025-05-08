# Cryptor

Assuming you want to encrypt and pack /usr/bin/socat:

1. make cryptor
2. ./cryptor /usr/bin/socat payload.h enc_payload secret_passphrase
3. make decryptor
4. ./decryptor secret_passphrase

