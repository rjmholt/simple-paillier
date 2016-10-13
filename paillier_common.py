"""
Common protocol, object structure and function implementation for a
Paillier cryptosystem suite, involving standard computation functions,
message object class definitions and computation response object definitions
"""

import math
import random
import json as json_lib
from collections import namedtuple

# ---- GENERAL USE FUNCTIONS FOR ENCRYPTION AND DECRYPTION ---- #

PrivateKey = namedtuple('PrivateKey', ['gLambda', 'gMu'])
PublicKey  = namedtuple('PublicKey',  ['n', 'g'])

def xgcd(a, b):
    """
    Finds the extended gcd results for integers b and n.

    Credit for the function is due to wikibooks.org:
    https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm#Python
    """
    a0 = a
    b0 = b

    x0, x1, y0, y1 = 1, 0, 0, 1
    while b != 0:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1

    assert a0*x0 + b0*y0 == math.gcd(a0, b0)
    return  a, x0, y0

def modinv(a, m):
    """
    Finds the modular inverse of a with respect to m if it exists, and throws
    an exception otherwise.

    Credit for this function goes to Märt Bakhoff on StackOverflow:
    https://stackoverflow.com/questions/4798654/modular-multiplicative-inverse-function-in-python
    """
    g, x, _ = xgcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        inv = x % m
        assert (inv * a) % m == 1
        return inv

def lcm(a, b):
    """
    Finds the least common multiple of two numbers. Relies on a simple
    mathematic identity.
    """

    v = a * b // math.gcd(a, b)
    assert v * math.gcd(a, b) == a * b
    return v

def generate_paillier_keys(p, q):
    """
    Given two primes, this generates a pair of Paillier keys, private and public
    """
    n = p * q
    gLambda = (p-1) * (q-1)
    g = n + 1

    gMu = None
    while gMu is None:
        try:
            u = pow(g, gLambda, n*n)
            l = (u-1) // n
            gMu = modinv(l, n)
        except:
            pass

    pr = PrivateKey(gLambda, gMu)
    pu = PublicKey(n, g)

    return pr, pu

def encrypt(msg, g, n):
    """
    Takes Paillier public key credentials and encrypts a message with them.
    """
    r = None
    while not r:
        v = random.randint(2, n*n)
        if math.gcd(v, n*n) == 1:
            r = v
    return encrypt_param(msg, g, n, r)

def encrypt_param(msg, g, n, r):
    """
    Encrypts a message with Paillier public key credentials and a given random
    number
    """
    k1 = pow(g, msg, n*n)
    k2 = pow(r, n, n*n)
    return (k1 * k2) % (n*n)

def decrypt(ciphertext, lam, mu, n):
    """
    Decrypts a given ciphertext with the given Paillier private credentials (and
    the modulo)
    """
    k1 = pow(ciphertext, lam, n*n)
    l  = (k1 - 1) // n
    return (l * mu) % n

# ---- MESSAGE PARSING EXCEPTIONS ---- #
class MessageParseError(Exception):
    """
    Exception thrown when a parsed message lacks a required field
    """
    def __init__(self, message):
        super().__init__()
        self.message = message

class PaillierComputationError(Exception):
    """
    Exception thrown when a remote computation has failed
    """
    def __init__(self, message):
        super().__init__()
        self.message = message

# ---- MESSAGE DISPATCH CLASSES ---- #

class PaillierMessage:
    """
    A Paillier computation request message to be sent to the homomorphic
    computation server
    """

    ADD = 'ADD'
    MUL = 'MUL'
    SUB = 'SUB'

    def toJson(self):
        """
        Returns this message as a JSON object (not a string)
        """
        pass

    def serialise(self):
        """
        Returns this message as a JSON string
        """
        return json_lib.dumps(self.toJson())

    def computeResult(self):
        """
        Return a PaillierResponse object with the result of the requested
        computation
        """
        pass

    @staticmethod
    def deserialise(json_str):
        """
        Takes a JSON string and returns a new Paillier message object. If the
        JSON is malformed or fields are missing, this will throw an exception.
        """
        return PaillierMessage.fromJson(json_lib.loads(json_str))

    @staticmethod
    def fromJson(json):
        """
        Takes a Python JSON object (a dict) and returns a Paillier message
        object if the fields are present. Throws an exception otherwise.
        """
        if 'type' in json:
            if json['type'] == PaillierMessage.ADD:
                return PaillierMessage.parseAdd(json)
            if json['type'] == PaillierMessage.MUL:
                return PaillierMessage.parseMul(json)
            if json['type'] == PaillierMessage.SUB:
                return PaillierMessage.parseSub(json)

        raise MessageParseError('No "type" field in message')

    @staticmethod
    def parseAdd(json):
        """
        Creates a PaillierAddMsg object from a JSON object if all required
        fields are present. Throws an exception otherwise.
        """
        if 'e1' not in json:
            raise MessageParseError('No "e1" field in message')
        if 'e2' not in json:
            raise MessageParseError('No "e2" field in message')
        if 'n' not in json:
            raise MessageParseError('No "n" field in message')

        return PaillierAddMsg(json['e1'], json['e2'], json['n'])

    @staticmethod
    def parseMul(json):
        """
        Creates a PaillierMulMsg object from a JSON object if all required
        fields are present. Throws an exception otherwise.
        """
        if 'ciphertext' not in json:
            raise MessageParseError('No "ciphertext" field in message')
        if 'multiplier' not in json:
            raise MessageParseError('No "multiplier field in message')
        if 'n' not in json:
            raise MessageParseError('No "n" field in message')

        return PaillierMulMsg(json['ciphertext'], json['multiplier'], json['n'])

    @staticmethod
    def parseSub(json):
        """
        Creates a PaillierSubMsg object form a JSON object if all required
        fields are present. Throws an exception otherwise.
        """
        if 'e1' not in json:
            raise MessageParseError('No "e1" field in message')
        if 'e2' not in json:
            raise MessageParseError('No "e2" field in message')
        if 'n' not in json:
            raise MessageParseError('No "n" field in message')

        return PaillierSubMsg(json['e1'], json['e2'], json['n'])

class PaillierAddMsg(PaillierMessage):
    """
    A Paillier computation  request message that requests the server take the
    two encrypted integers e1 and e2 and add them modulo n.
    """

    def __init__(self, e1, e2, n):
        self.e1 = e1
        self.e2 = e2
        self.n  = n

    def toJson(self):
        """
        Returns a JSON representation of this message.
        """
        obj = {
            'type': self.ADD,
            'e1':   self.e1,
            'e2':   self.e2,
            'n':    self.n
        }

        return obj

    def computeResult(self):
        """
        Compute the result of (e1 * e2) % (n^2) and return the result in a
        PaillierAddResponse object
        """
        result = (self.e1 * self.e2) % (self.n * self.n)
        return PaillierAddResponse(result)

    @staticmethod
    def fromValues(g, n, m1, m2):
        """
        Creates a new object of this type from given values
        """
        e1 = encrypt(m1, g, n)
        e2 = encrypt(m2, g, n)

        return PaillierAddMsg(e1, e2, n)


class PaillierMulMsg(PaillierMessage):
    """
    A Paillier computation request message that sends an encrypted integer x and
    a plaintext integer m, with the expectation that the server can return the
    encrypted result of x * m % n
    """
    def __init__(self, x, m, n):
        self.x = x
        self.m = m
        self.n = n

    def toJson(self):
        """
        Return a JSON representation of this message
        """
        obj = {
            'type':         self.MUL,
            'ciphertext':   self.x,
            'multiplier':   self.m,
            'n':            self.n
        }

        return obj

    def computeResult(self):
        """
        Compute (x ^ m) % (n^2) and return the result as a PaillierMulResponse
        object
        """
        result = pow(self.x, self.m, self.n * self.n)
        return PaillierMulResponse(result)

    @staticmethod
    def fromValues(g, n, msg, multiplier):
        """
        Create a new message of this type from given values
        """
        x = encrypt(msg, g, n)
        return PaillierMulMsg(x, multiplier, n)


class PaillierSubMsg(PaillierMessage):
    """
    A Paillier computation request message that sends an encrypted integer x and
    a plaintext integer m, with the expectation that the server can return the
    encrypted result of x * m % n
    """
    def __init__(self, e1, e2, n):
        self.e1 = e1
        self.e2 = e2
        self.n  = n

    def toJson(self):
        """
        Return a JSON representation of this message
        """
        obj = {
            'type': self.SUB,
            'e1':   self.e1,
            'e2':   self.e2,
            'n':    self.n
        }

        return obj

    def computeResult(self):
        """
        Compute (x ^ m) % (n^2) and return the result as a PaillierMulResponse
        object
        """
        neg_e2 = modinv(self.e2, self.n * self.n)
        result = (self.e1 * neg_e2) % (self.n * self.n)
        return PaillierSubResponse(result)

    @staticmethod
    def fromValues(g, n, m1, m2):
        """
        Create a new message of this type from given values
        """
        e1 = encrypt(m1, g, n)
        e2 = encrypt(m2, g, n)
        return PaillierSubMsg(e1, e2, n)

# ---- MESSAGE RESPONSE CLASSES ---- #

class PaillierResponse:
    """
    The response from a server with the result of a request homomorphic
    computation.
    """

    ERROR    = 'ERROR'
    ADD_RESP = 'ADD_RESP'
    MUL_RESP = 'MUL_RESP'
    SUB_RESP = 'SUB_RESP'

    def __init__(self, msgType, result):
        self.msgType = msgType
        self.result  = result

    def toJson(self):
        """
        Return a JSON representation of this message
        """
        obj = {
            'type':   self.msgType,
            'result': self.result
        }

        return obj

    def decryptResult(self, gLambda, gMu, n):
        """
        Decrypt the contents of this message using the given private Paillier
        parameters and return the result
        """
        return decrypt(self.result, gLambda, gMu, n)

    def serialise(self):
        """
        Return this message as a JSON-encoded string
        """
        return json_lib.dumps(self.toJson())

    @staticmethod
    def deserialise(json_str):
        """
        Take a JSON-encoded string and decode it into a PaillierResponse object.
        If the JSON is malformed or has missing required fields this will throw
        an exception.
        """
        return PaillierResponse.fromJson(json_lib.loads(json_str))

    @staticmethod
    def fromJson(json):
        """
        Take a Python JSON object (a dict) and return the PaillierResponse
        object it encodes. If required fields are not present, throw an
        exception.
        """
        if 'type' in json:
            if json['type'] == PaillierResponse.ADD_RESP:
                return PaillierResponse.parseAddResponse(json)
            if json['type'] == PaillierResponse.MUL_RESP:
                return PaillierResponse.parseMulResponse(json)
            if json['type'] == PaillierResponse.ERROR:
                return PaillierResponse.parseErrorReponse(json)
            if json['type'] == PaillierResponse.SUB_RESP:
                return PaillierResponse.parseSubResponse(json)

        raise MessageParseError('No "type" field in message')

    @staticmethod
    def parseAddResponse(json):
        """
        Parse a JSON object into a PaillierAddResponse object
        """
        if 'result' in json:
            return PaillierAddResponse(json['result'])
        raise MessageParseError('No "result" field in message')

    @staticmethod
    def parseMulResponse(json):
        """
        Parse a JSON object into a PaillierMulResponse object
        """
        if 'result' in json:
            return PaillierMulResponse(json['result'])
        raise MessageParseError('No "result" field in message')

    @staticmethod
    def parseSubResponse(json):
        """
        Parse a JSON object into a PaillierSubResponse object
        """
        if 'result' in json:
            return PaillierSubResponse(json['result'])
        raise MessageParseError('No "result" field in message')

    @staticmethod
    def parseErrorReponse(json):
        """
        Parse a JSON object into a PaillierErrorResponse object
        """
        if 'result' in json:
            return PaillierErrorResponse(json['result'])
        raise MessageParseError('No "result" field in message')

class PaillierAddResponse(PaillierResponse):
    """
    An object encoding the result of a Paillier homomorphically encrypted
    addition request
    """
    def __init__(self, result):
        super().__init__(PaillierResponse.ADD_RESP, result)

class PaillierMulResponse(PaillierResponse):
    """
    An object encoding the result of a Paillier homomorphically encrypted
    multiplication request
    """
    def __init__(self, result):
        super().__init__(PaillierResponse.MUL_RESP, result)

class PaillierSubResponse(PaillierResponse):
    """
    An object encoding the result of a Paillier homomorphically encrypted
    multiplication request
    """
    def __init__(self, result):
        super().__init__(PaillierResponse.SUB_RESP, result)

class PaillierErrorResponse(PaillierResponse):
    """
    Encodes the possibility of a computation error on the server
    """
    def __init__(self, error_message=None):
        if error_message:
            super().__init__(PaillierResponse.ERROR, error_message)
        else:
            super().__init__(PaillierResponse.ERROR, "error")

    def decryptResult(self, *_args):
        """
        Throws the error sent
        """
        raise PaillierComputationError(self.result)
