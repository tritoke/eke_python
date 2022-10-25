#!/usr/bin/env python

import argparse
import getpass
import os
import socket
import sys
from base64 import b64decode
from eke import *
from json_mixins import JsonClient
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class EKE(JsonClient):
    def __init__(self, username, password, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.username = username
        self.password = password
        self.I = b2l(username.encode())
        self.p = b2l(password.encode())


    def register(self):
        # send a register command
        self.send_json(action="register", username=self.username, password=self.password)

        # receive the status back
        self.recv_json()
        if self.data["success"]:
            print(self.data["message"])
        else:
            print("Failed to register user.")


    def negotiate(self):
        # generate random public key Ea
        Ea = RSA.gen()

        # instantiate AES with the password
        P = AES.new(self.password.ljust(16).encode(), AES.MODE_ECB)

        # send a negotiate command
        self.send_json(
            action="negotiate",
            username=self.username,
            enc_pub_key=b64e(P.encrypt(Ea.encode_public_key())),
            modulus=Ea.n
        )

        # receive and decrypt R
        self.recv_json()
        key = l2b(Ea.decrypt(b2l(P.decrypt(b64d(self.data["enc_secret_key"])))))
        R = AES.new(key, AES.MODE_ECB)

        # send first challenge
        challengeA = randbytes(16)
        self.send_json(challenge_a=b64e(R.encrypt(challengeA)))

        # receive challenge response
        self.recv_json()
        challenge_response = R.decrypt(b64d(self.data["challenge_response"]))

        assert challenge_response[:16] == challengeA, "Challenge A failed."

        challengeB = challenge_response[16:]

        # response with challengeB
        self.send_json(challenge_b=b64e(R.encrypt(challengeB)))

        # receive success message
        self.recv_json()
        assert self.data["success"], self.data.get("message", "ChallengeB failed.")

        # store the shared key
        self.R = R

    def send_message(self, message: str):
        encoded_message = b64e(self.R.encrypt(message.encode().ljust(len(message) + (16 - (len(message) % 16)))))
        self.send_json(
            action="send_message",
            message=encoded_message,
        )


def main():
    DEFAULT_HOST = os.getenv("HOST", "localhost")
    DEFAULT_PORT = int(os.getenv("PORT", "12345"))

    parser = argparse.ArgumentParser(description="Client for EKE.")
    parser.add_argument("action",   help="The action to perform (register|negotiate)")
    parser.add_argument("--host",   help="The host to connect to.", default=DEFAULT_HOST)
    parser.add_argument("--port",   help="The port to connect to.", default=DEFAULT_PORT, type=int)
    parser.add_argument("--user",   help="The username to use in the protocol.")
    parser.add_argument("--passwd", help="The password to use in the protocol.")
    parser.add_argument("--debug",  help="Enable debug logging", default=0, type=int)

    args = parser.parse_args()
    HOST = args.host
    PORT = args.port

    debug_recv = args.debug & 1 == 1
    debug_send = args.debug & 2 == 2

    action = args.action
    if action not in ["register", "negotiate"]:
        print(f"Unrecognised action: \"{action}\"")
        sys.exit(-1)

    username = args.user if args.user else input("Username: ")
    password = args.passwd if args.passwd else getpass.getpass("Password: ")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))

        eke = EKE(
            username,
            password,
            conn=sock,
            debug_send=debug_send,
            debug_recv=debug_recv
        )

        try:
            if action == "register":
                eke.register()
            else:
                eke.negotiate()
                msg = input("message: ")
                eke.send_message(msg)
        except KeyError:
            if "success" not in eke.data:
                raise

            success = eke.data["success"]
            if "message" in eke.data:
                message = eke.data["message"]
                print(f"Caught exception: {success = } - {message}")
            else:
                print(f"Caught exception: success={success}")


if __name__ == "__main__":
    main()

