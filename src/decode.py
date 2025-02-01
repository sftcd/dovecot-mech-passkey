#!/usr/bin/env python3

from base64 import b64decode, b64encode
import uuid
import struct

DATA = b64decode("")

aaguid = uuid.UUID(bytes=DATA[0:16])
(cred_len,) = struct.unpack(">H", DATA[16:18])
cred_id = DATA[18:18+cred_len]
pubkey = DATA[18+cred_len:]
print(b64encode(pubkey).decode())
