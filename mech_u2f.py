#!/usr/bin/env python3

## To use, pip install fido2
## with NFC, use pip install fido2[pcsc]

## Usage:
##
## python3 mech_u2f.py register
## Generates an attested credential for long term storage
##
## python3 mech_u2f.py auth <attested credential>
## Authenticates user against the stored credential
##

from fido2 import cbor
from fido2.hid import CtapHidDevice
from fido2.utils import ByteBuffer, websafe_encode, websafe_decode
from fido2.client import Fido2Client, WindowsClient, UserInteraction
from fido2.server import Fido2Server
from fido2.webauthn import (
    AttestedCredentialData,
    Aaguid,
    CoseKey,
    AuthenticatorAssertionResponse,
)
from base64 import b64encode, b64decode
from getpass import getpass
import json
import ctypes
import sys
import logging


class CliInteraction(UserInteraction):
    def prompt_up(self):
        print("\nTouch your authenticator device now...\n")

    def request_pin(self, permissions, rd_id):
        return getpass("Enter PIN: ")

    def request_uv(self, permissions, rd_id):
        print("User Verification required.")
        return True


## SASL flow:
## Server sends nothing
## Client sends username
## Server sends fido2 challenge
## Client sends fido2 response
class PASSKEYAuthenticator:
    def __init__(self, user, client=None, appid="https://imap.example.com"):
        self.logger = logging.getLogger(self.__class__.__name__)

        if client is None:
            self.client = self.find_client(appid)
        else:
            self.client = client

        self.user = user

    def __call__(self, response):
        if len(response) == 0:
            return self.user.encode()
        else:
            # decode challenge
            req = cbor.decode(response)
            result = self.client.get_assertion(req)
            return cbor.encode(result.get_response(0))

    def find_dev(self):
        # Locate a device
        dev = next(CtapHidDevice.list_devices(), None)
        if dev is not None:
            self.logger.debug("Use USB HID channel.")
        else:
            try:
                from fido2.pcsc import CtapPcscDevice

                dev = next(CtapPcscDevice.list_devices(), None)
                self.logger.debug("Use NFC channel.")
            except Exception as e:
                self.logger.error("NFC channel search error:", e)

        if not dev:
            self.logger.error("No FIDO device found")
            sys.exit(1)

        return dev

    def find_client(self, appid):
        if WindowsClient.is_available() and not ctypes.windll.shell32.IsUserAnAdmin():
            # Use the Windows WebAuthn API if available, and we're not running as admin
            return WindowsClient(appid)

        dev = self.find_dev()
        print(dev)
        return Fido2Client(dev, appid, user_interaction=CliInteraction())


def authn(data):
    # decode cred
    if not data.startswith("{PASSKEY}"):
        logging.error("Credential does not start with {PASSKEY}")
        sys.exit(1)

    mech = PASSKEYAuthenticator("user_id", appid="https://imap.example.com")

    user = mech("")

    # would then fetch AttestedCredentialData for user from somewhere.

    credential, _ = AttestedCredentialData.unpack_from(b64decode(data[9:]))
    uv = "preferred"
    server = Fido2Server(
        {"id": "imap.example.com", "name": "Example RP"}, attestation="direct"
    )
    request_options, state = server.authenticate_begin(
        [credential], user_verification=uv
    )

    result = cbor.decode(mech(cbor.encode(request_options.public_key)))
    result = AuthenticatorAssertionResponse(
        client_data=result["clientDataJSON"],
        authenticator_data=result["authenticatorData"],
        signature=result["signature"],
        credential_id=result["credentialId"],
        extension_results=result["extensionResults"],
    )

    server.authenticate_complete(
        state,
        [credential],
        result["credentialId"],
        result["clientDataJSON"],
        result["authenticatorData"],
        result["signature"],
    )


def reg():
    logging.basicConfig(level=logging.DEBUG)
    mech = PASSKEYAuthenticator("user_id", appid="https://imap.example.com")
    client = mech.find_client("https://imap.example.com")
    uv = "preferred"
    server = Fido2Server(
        {"id": "imap.example.com", "name": "Example RP"}, attestation="direct"
    )
    user = {"id": b"testuser", "name": "A. User"}
    create_options, state = server.register_begin(
        user, user_verification=uv, authenticator_attachment="cross-platform"
    )
    result = client.make_credential(create_options["publicKey"])
    auth_data = server.register_complete(
        state, result.client_data, result.attestation_object
    )
    buf = ByteBuffer()
    buf.write(auth_data.credential_data)

    print("{PASSKEY}%s" % b64encode(buf.getbuffer().tobytes()).decode())


def main():
    if len(sys.argv) < 2:
        print("Usage: test.py auth <credential>|register")
    elif sys.argv[1] == "auth" and len(sys.argv) > 2:
        authn(sys.argv[2])
    elif sys.argv[1] == "register":
        reg()
    else:
        print("Usage: test.py auth <credential>|register")


if __name__ == "__main__":
    main()
