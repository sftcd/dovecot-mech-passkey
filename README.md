Things to add

 - Support multiple passkeys
    - They go into the allowed_keys array
 - Decode public key only for matching public key after response
 (saves a lot of cycles too in case there was no response)
 - Clean up the code a lot
    - parse each key type separately
    - need to add support for raw RSA key loading
    - not sure how to test PS256, RS256
        - software passkey?
    - make a mech_u2f.py for python3 IMAP/POP3 for testing
    - support generating fido2 credentials when hidraw2 is available?
    - cleanup cbor usage
    - should it use some kind of GS2 header or smth instead
      of just username?
 - Settings:
    passkey_domain = example.org
    passkey_timeout = 60s
