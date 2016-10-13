simple-pailler
==============

This is a very simple implementation of the Paillier cryptosystem.

It allows a demonstration of the homomorphic addition and subtraction properties
of the system, as well as the semi-homomorphic multiplication property.

To run it, ensure you have Python 3 installed, and run the server (after
configuring the port as required) with `./paillier_server.py`. Then, with the
client similarly configured, just run `./paillier_client.py`.

Possible changes/improvements to make:
    * Allow host/port as commandline arguments
    * Refactor `paillier_common.py` to be less repetitive
    * Couple with ElGamal to obtain fully homomorphic encryption
      (modulo network exchanges)
    * Create a small (perhaps Lisp-like) evaluation language for such
      homomorphic expressions
