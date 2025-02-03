#!/usr/bin/env python3
from base64 import b64decode
from fido2.ctap2 import AttestedCredentialData
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, EllipticCurvePublicKey

with open("cred", "r") as cred_in:
    cred = b64decode(cred_in.readline().strip()[9:])


def tag_hook(decoder, tag):
    print(tag)


def object_hook(decoder, obj):
    print(obj)


(data, _) = AttestedCredentialData.unpack_from(cred)
pk = data.public_key
print(pk)
x = pk[-2]
y = pk[-3]

pubkey = EllipticCurvePublicKey.from_encoded_point(SECP256R1(), x+y)
