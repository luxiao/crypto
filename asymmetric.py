# -*- coding: utf-8 -*-
# requirements: cryptography==1.4
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from collections import OrderedDict
import json
from base64 import b64decode, b64encode

MAX_ENCRYPT_SIZE = 117
MAX_DECRYPT_SIZE = 128


class PrivateKey(object):
    @classmethod
    def init_from_file(cls, key_path, password=None):
        key_file = open(key_path, "rb")
        return cls(key_file.read(), password=password)

    def __init__(self, key_block, password=None):
        self.priv = serialization.load_pem_private_key(
            key_block, password=password, backend=default_backend())
        self.pub = self.priv.public_key()

    def sign(self, msg):
        sign = self.priv.sign(
            msg,
            padding.PKCS1v15(),
            hashes.SHA1()
        )
        return sign

    def _verify(self, signature, msg):
        verify = self.pub.verify(
            signature,
            msg,
            padding.PKCS1v15(),
            hashes.SHA1()
        )
        return verify

    def verify(self, signature, msg):
        try:
            self._verify(signature, msg)
            return True
        except InvalidSignature as e:
            print str(e)
            return False

    def encrypt(self, msg):
        cipher = ''
        if len(msg) <= MAX_ENCRYPT_SIZE:
            cipher = self.pub.encrypt(
                msg,
                padding.PKCS1v15()
            )
        else:
            offset = 0
            while offset < len(msg):
                end = offset + MAX_ENCRYPT_SIZE
                cipher += self.encrypt(msg[offset: end])
                offset = end
        return cipher

    def decrypt(self, cipher):
        plain = ''
        if len(cipher) <= MAX_DECRYPT_SIZE:
            plain = self.priv.decrypt(
                cipher,
                padding.PKCS1v15()
            )
        else:
            offset = 0
            while offset < len(cipher):
                end = offset + MAX_DECRYPT_SIZE
                plain += self.decrypt(cipher[offset: end])
                offset = end
        return plain


class PublicKey(object):
    def __init__(self, key_block):
        self.pub = serialization.load_pem_public_key(
            key_block,
            backend=default_backend()
        )

    def verify(self, sign, msg):
        try:
            self.pub.verify(sign, msg, padding.PKCS1v15(), hashes.SHA1())
            return True
        except InvalidSignature as e:
            print str(e)
            return False


def rc4(data, key):
    """RC4 encryption and decryption method."""
    S, j, out = list(range(256)), 0, []

    for i in range(256):
        j = (j + S[i] + ord(key[i % len(key)])) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0
    for ch in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(chr(ord(ch) ^ S[(S[i] + S[j]) % 256]))

    return "".join(out)


def main(http_body):
    sign = http_body.pop('sign')
    signature = b64decode(sign)
    ordered = OrderedDict(sorted(http_body.items(), key=lambda x: x[0]))
    msg = json.dumps(ordered).replace(' ','').encode('utf-8')
    #  public key verify
    _pub_file = open('open_rsa_public_key.pem').read()
    _pub_key = PublicKey(_pub_file)
    verify = _pub_key.verify(signature, msg)
    if not verify:
        print 'verify false'
        return
    # your private key decrypt
    your_priv_file = open('open_rsa_private_key.pem').read()
    your_priv_key = PrivateKey(your_priv_file)
    biz = b64decode(http_body['bizContent'])
    plain_biz = your_priv_key.decrypt(biz)
    print plain_biz
    # rc4 decrypt bizContent
    plain_biz = json.loads(plain_biz)
    biz2 = plain_biz['bizContent'].decode('hex')
    rc4_key = b'your_key'
    plain_biz2 = rc4(biz2, rc4_key)
    plain_biz['bizContent'] = plain_biz2
    return plain_biz


if __name__ == '__main__':
    http_body = {"sign":"""your_base64_encoded_signature=""","timestamp":"20170608143728543","bizContent":"""your_bizContent==""","signType":"RSA","charset":"UTF-8","format":"json","serviceName":"test.api"}
    print json.dumps(main(http_body)
