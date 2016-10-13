import paillier_common as paillier
import pc_old as pc
import random
import math

def encrypt_test():
    pass

def decrypt_test():
    pass

def xgcd_test():
    pass

def modinv_test():
    pass

def lcm_test():
    pass

def encrypt_symmetric_test():
    p = 17
    q = 19

    assert math.gcd(p*q, (p-1)*(q-1)) == 1

    pr, pu = paillier.generate_paillier_keys(p, q)

    v = random.randint(0, pu.n-1)

    e = paillier.encrypt(v, pu.g, pu.n)
    m = paillier.decrypt(e, pr.gLambda, pr.gMu, pu.n)

    print('m:', m)
    print('v:', v)
    assert m == v

    print('encrypt_symmetric_test: PASSED')

def paillier_add_message_test():
    p = 17
    q = 19

    assert math.gcd(p*q, (p-1)*(q-1)) == 1

    pr, pu = paillier.generate_paillier_keys(p, q)

    v1 = random.randint(0, pu.n-1)
    v2 = random.randint(0, pu.n-1)

    msg = paillier.PaillierAddMsg.fromValues(pu.g, pu.n, v1, v2)

    assert msg.__class__ is paillier.PaillierAddMsg
    assert msg.e1 == paillier.encrypt(v1, pu.g, pu.n)
    assert msg.e2 == paillier.encrypt(v2, pu.g, pu.n)

    result = msg.computeResult()

    assert result.__class__ is paillier.PaillierMulResponse
    assert result.result == (msg.e1 * msg.e2) % (pu.n * pu.n)
    assert result.decryptResult(pr.gLambda, pr.gMu, pu.n) == v1 + v2

if __name__ == '__main__':
    for _ in range(20):
        paillier_add_message_test()
