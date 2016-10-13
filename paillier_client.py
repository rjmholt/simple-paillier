#!/usr/local/bin/python3
"""
A primitive client for a networked Paillier cryptosystem. This prompts the user
for their desired function and values, encrypts them with the hardcoded prime
parameters and sends them to the server for computation. When it receives a
response, it decrypts the result and prints it.
"""

import socket
import sys

import paillier_common as paillier

if __name__ == '__main__':
    REMOTE_HOST = 'localhost'
    PORT = 1337

    P = 2193992993218604310884461864618001945131790925282531768679169054389241527895222169476723691605898517
    Q = 7212610147295474909544523785043492409969382148186765460082500085393519556525921455588705423020751421

    privateKey, publicKey = paillier.generate_paillier_keys(P, Q)

    scenario = None
    msg = None
    while True:
        scenario = input('Please choose from "add", "mul" or "sub": ')
        if scenario == 'add':
            n1 = int(input('n1: '))
            n2 = int(input('n2: '))
            msg = paillier.PaillierAddMsg.fromValues(publicKey.g,
                                                     publicKey.n,
                                                     n1, n2)
            break

        elif scenario == 'mul':
            n = int(input('n (to encrypt): '))
            m = int(input('m (plaintext multiplier): '))
            msg = paillier.PaillierMulMsg.fromValues(publicKey.g,
                                                     publicKey.n,
                                                     n, m)
            break

        elif scenario == 'sub':
            n1 = int(input('n1: '))
            n2 = int(input('n2: '))
            msg = paillier.PaillierSubMsg.fromValues(publicKey.g,
                                                     publicKey.n,
                                                     n1, n2)
            break

        print('Please enter either "add", "mul" or "sub"')

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        sock.connect((REMOTE_HOST, PORT))
        print('msg:', msg.serialise())
        msg_bytes = bytes(msg.serialise(), 'utf8')
        sock.sendall(msg_bytes)
        response = sock.recv(20000)
        print(response)

        if not response:
            sys.exit(1)

        paillier_reponse = paillier.PaillierResponse.deserialise(str(response, 'utf8'))

        result = paillier_reponse.decryptResult(privateKey.gLambda,
                                                privateKey.gMu,
                                                publicKey.n)
        print('result:', result)
    finally:
        sock.close()
