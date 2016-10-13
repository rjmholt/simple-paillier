#!/usr/local/bin/python3
"""
A small server for the Paillier cryptosystem. This receives messages with
encrypted payloads and depending on the message type performs the correct
computation. This server is able to compute results, but cannot decrypt the
encrypted parts of the payloads it receives.
"""

import socketserver

import paillier_common as paillier

class PaillierHandler(socketserver.BaseRequestHandler):
    """
    A sockerserver Request Handler implementation for a Paillier computation
    server. This receives JSON strings over TCP, deserialises them according to
    the paillier_common library, performs the required computation, and sends
    back a serialised response as a JSON-encoded string
    """

    def handle(self):
        """
        Handle TCP requests from a client sending JSON-encoded Paillier
        computation requests
        """
        data = str(self.request.recv(20000), 'utf8')
        print(data)

        result = None
        try:
            pMsg = paillier.PaillierMessage.deserialise(data)
            result = pMsg.computeResult()
        except paillier.MessageParseError as e:
            result = paillier.PaillierErrorResponse(error_message=e.message)

        response = bytes(result.serialise(), 'utf8')
        self.request.sendall(response)

if __name__ == '__main__':
    HOST = 'localhost'
    PORT = 1337

    server = socketserver.TCPServer((HOST, PORT), PaillierHandler)

    server.serve_forever()
