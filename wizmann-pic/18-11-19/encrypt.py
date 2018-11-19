#!/usr/bin/env python
#
# Copyright 2012-2015 clowwindy
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from __future__ import absolute_import, division, print_function, \
    with_statement

import os
import sys
import hashlib
import logging
import random
import string
import binascii

from shadowsocks import common
from shadowsocks.crypto import rc4_md5, openssl, sodium, table

NONCE_RANGE = (32, 512)
NONCE_CONSTANT = binascii.unhexlify('deadbeef')

def make_nonce():
    nonce_length = random.randint(*NONCE_RANGE)
    nonce = ''.join(
            [random.choice(string.ascii_letters) for i in xrange(nonce_length)])
    return NONCE_CONSTANT + nonce + NONCE_CONSTANT

method_supported = {}
method_supported.update(rc4_md5.ciphers)
method_supported.update(openssl.ciphers)
method_supported.update(sodium.ciphers)
method_supported.update(table.ciphers)


def random_string(length):
    return os.urandom(length)


cached_keys = {}


def try_cipher(key, method=None):
    Encryptor(key, method)


def EVP_BytesToKey(password, key_len, iv_len):
    # equivalent to OpenSSL's EVP_BytesToKey() with count 1
    # so that we make the same key and iv as nodejs version
    cached_key = '%s-%d-%d' % (password, key_len, iv_len)
    r = cached_keys.get(cached_key, None)
    if r:
        return r
    m = []
    i = 0
    while len(b''.join(m)) < (key_len + iv_len):
        md5 = hashlib.md5()
        data = password
        if i > 0:
            data = m[i - 1] + password
        md5.update(data)
        m.append(md5.digest())
        i += 1
    ms = b''.join(m)
    key = ms[:key_len]
    iv = ms[key_len:key_len + iv_len]
    cached_keys[cached_key] = (key, iv)
    return key, iv


class Encryptor(object):
    def __init__(self, key, method):
        self.key = key
        self.method = method
        self.iv = None
        self.iv_sent = False
        self.cipher_iv = b''
        self.decipher = None
        method = method.lower()
        self._method_info = self.get_method_info(method)
        self.obf_buffer = ''
        self.obf_max_length = random.randint(NONCE_RANGE[1], 4096)
        self.obf_flag = 0
        if self._method_info:
            self.cipher = self.get_cipher(key, method, 1,
                                          random_string(self._method_info[1]))
        else:
            logging.error('method %s not supported' % method)
            sys.exit(1)

    def get_method_info(self, method):
        method = method.lower()
        m = method_supported.get(method)
        return m

    def iv_len(self):
        return len(self.cipher_iv)

    def get_cipher(self, password, method, op, iv):
        password = common.to_bytes(password)
        m = self._method_info
        if m[0] > 0:
            key, iv_ = EVP_BytesToKey(password, m[0], m[1])
        else:
            # key_length == 0 indicates we should use the key directly
            key, iv = password, b''

        iv = iv[:m[1]]
        if op == 1:
            # this iv is for cipher not decipher
            self.cipher_iv = iv[:m[1]]
        return m[2](method, key, iv, op)

    def encrypt(self, buf):
        if len(buf) == 0:
            return buf
        if self.iv_sent:
            return self.cipher.update(buf)
        else:
            self.iv_sent = True
            nonce = make_nonce()
            return self.cipher_iv + self.cipher.update(nonce + buf)

    def decrypt(self, buf):
        if len(buf) == 0:
            return buf

        if self.obf_flag == -1:
            return ''

        if self.decipher is None:
            decipher_iv_len = self._method_info[1]
            decipher_iv = buf[:decipher_iv_len]
            self.decipher = self.get_cipher(self.key, self.method, 0,
                                            iv=decipher_iv)
            buf = buf[decipher_iv_len:]
            if len(buf) == 0:
                return buf
        res = self.decipher.update(buf)
        self.obf_buffer += res

        if self.obf_flag:
            return res

        if self.obf_buffer.startswith(NONCE_CONSTANT) \
                and self.obf_buffer.index(NONCE_CONSTANT, 1) > 0:
            self.obf_flag = 1
            pos = self.obf_buffer.index(NONCE_CONSTANT, 1)
            return self.obf_buffer[pos + len(NONCE_CONSTANT):]
        elif len(self.obf_buffer) > self.obf_max_length:
            self.obf_flag = -1

        return ''

def encrypt_all(password, method, op, data):
    result = []
    method = method.lower()
    (key_len, iv_len, m) = method_supported[method]
    if key_len > 0:
        key, _ = EVP_BytesToKey(password, key_len, iv_len)
    else:
        key = password
    if op:
        iv = random_string(iv_len)
        result.append(iv)

        nonce = make_nonce()
        data = nonce + data

        cipher = m(method, key, iv, op)
        result.append(cipher.update(data))
        return b''.join(result)
    else:
        iv = data[:iv_len]
        data = data[iv_len:]

        cipher = m(method, key, iv, op)
        data = cipher.update(data)

        if data.startswith(NONCE_CONSTANT) and data.index(NONCE_CONSTANT, 1) > 0:
            pos = data.index(NONCE_CONSTANT, 1)
            data = data[pos + len(NONCE_CONSTANT):]
        else:
            data = ''

        return data


CIPHERS_TO_TEST = [
    'aes-128-cfb',
    'aes-256-cfb',
    'rc4-md5',
    'salsa20',
    'chacha20',
    'table',
]


def test_encryptor():
    from os import urandom
    plain = urandom(10240)
    for method in CIPHERS_TO_TEST:
        logging.warn(method)
        encryptor = Encryptor(b'key', method)
        decryptor = Encryptor(b'key', method)
        for i in xrange(100):
            cipher = encryptor.encrypt(plain)
            plain2 = decryptor.decrypt(cipher)
            assert plain == plain2


def test_encrypt_all():
    from os import urandom
    plain = urandom(10240)
    for method in CIPHERS_TO_TEST:
        logging.warn(method)
        cipher = encrypt_all(b'key', method, 1, plain)
        plain2 = encrypt_all(b'key', method, 0, cipher)
        assert plain == plain2


if __name__ == '__main__':
    test_encrypt_all()
    test_encryptor()

