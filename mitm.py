#!/usr/bin/env python

import argparse
import errno
import fcntl
import os
import socket
import threading
import time


def main():
    DEFAULT_HOST = os.getenv("HOST", "localhost")
    DEFAULT_PORT = int(os.getenv("PORT", "12345"))

    parser = argparse.ArgumentParser(description="Partition attack against EKE.")
    parser.add_argument("--host",   help="The host to connect to.", default=DEFAULT_HOST)
    parser.add_argument("--port",   help="The port to connect to.", default=DEFAULT_PORT, type=int)
    parser.add_argument("--listen", help="The port to listen on.", default=DEFAULT_PORT + 1, type=int)
    parser.add_argument("--debug",  help="Enable debug logging", default=0, type=int)

    args = parser.parse_args()

    global HOST, PORT, LISTEN
    HOST = args.host
    PORT = args.port
    LISTEN = args.listen

    debug_recv = args.debug & 1 == 1
    debug_send = args.debug & 2 == 2

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listen_sock:
        listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # bind on all interfaces
        listen_sock.bind(("0.0.0.0", LISTEN))
        listen_sock.listen(10)

        while True:
            conn, addr = listen_sock.accept()
            # set non-blocking IO
            fcntl.fcntl(conn, fcntl.F_SETFL, os.O_NONBLOCK)

            threading.Thread(target=process, args=(conn, addr)).start()



def process(incoming, addr):
    packet_log = []

    def fwd(a, b):
        # try to receive from a
        data = None
        try:
            data = a.recv(4096)
        except socket.error as e:
            err = e.args[0]
            if err != errno.EAGAIN and err != errno.EWOULDBLOCK:
                raise

        if data:
            print(f"[process.fwd] forwarding {data = }")
            b.sendall(data)
            packet_log.append(data)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as outgoing:
        outgoing.connect((HOST, PORT))
        fcntl.fcntl(outgoing, fcntl.F_SETFL, os.O_NONBLOCK)

        while True:
            # connect the two sockets
            i2o = fwd(incoming, outgoing)
            o2i = fwd(outgoing, incoming)

            # sleep for .2 seconds so as not to burn CPU power
            time.sleep(0.2)

if __name__ == "__main__":
    main()

