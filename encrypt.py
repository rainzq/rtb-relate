""" A python implementation of Google's RTB winning price encrypter """
#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
import time
import datetime
import hmac
import logging
import base64
import struct
from hashlib import sha1

def time_encode():
    now = time.time()
    sec = long(now)
    usec = long(now * 1000000 % 1000000)
    # only the first 8 bytes are valid to represent time
    return struct.pack('>iiii', sec, usec, sec, usec)

def time_decode(iv):
    time = struct.unpack('>ii', iv[:8])
    seconds = time[0] + time[1] / 1000000.0
    return datetime.datetime.fromtimestamp(seconds)


class PriceEncoder(object):
    def __init__(self, e_key, i_key):
        self.e_key = bytearray(e_key)
        self.i_key = bytearray(i_key)
        self.iv = bytearray(time_encode())
        assert len(self.e_key) == 32
        assert len(self.i_key) == 32
        assert len(self.iv) == 16

    def encode(self, price):
        """
        https://developers.google.com/ad-exchange/rtb/response-guide/decrypt-price
        """
        pad = hmac.new(self.e_key, self.iv, sha1).digest()
        assert len(pad) == 20
        # to network byte order
        price = struct.pack('>q', price)
        price = bytearray(price)
        enc_price = map(lambda x: x[0] ^ x[1], zip(price, bytearray(pad[:8])))
        enc_price = bytearray(enc_price)
        signature = hmac.new(self.i_key, price + self.iv, sha1).digest()
        assert len(signature) == 20
        msg = self.iv + enc_price + bytearray(signature[:4])
        final_msg = base64.urlsafe_b64encode(msg)
        return final_msg.rstrip('=')

    def decode(self, data):
        """
        https://developers.google.com/ad-exchange/rtb/response-guide/decrypt-price
        """
        assert len(data) == 38
        # padding to align 4 bytes
        data += '=' * ((4 - len(data) % 4) % 4)
        msg = base64.urlsafe_b64decode(data)
        assert len(msg) == 28
        iv, enc_price, signature = msg[:16], msg[16:24], msg[-4:]
        pad = hmac.new(self.e_key, iv, sha1).digest()
        assert len(pad) == 20
        price = map(lambda x: x[0] ^ x[1], zip(bytearray(enc_price), bytearray(pad)))
        price = bytearray(price)
        conf_signature = hmac.new(self.i_key, price + iv, sha1).digest()[:4]
        price = struct.unpack('>q', str(price))[0]
        time = time_decode(iv)
        if conf_signature == signature:
            return (price, time)
        return None

if __name__ == '__main__':
    e_key = (
      0xb0, 0x8c, 0x70, 0xcf, 0xbc, 0xb0, 0xeb, 0x6c, 0xab, 0x7e, 0x82, 0xc6,
      0xb7, 0x5d, 0xa5, 0x20, 0x72, 0xae, 0x62, 0xb2, 0xbf, 0x4b, 0x99, 0x0b,
      0xb8, 0x0a, 0x48, 0xd8, 0x14, 0x1e, 0xec, 0x07)
    i_key = (
      0xbf, 0x77, 0xec, 0x55, 0xc3, 0x01, 0x30, 0xc1, 0xd8, 0xcd, 0x18, 0x62,
      0xed, 0x2a, 0x4c, 0xd2, 0xc7, 0x6a, 0xc3, 0x3b, 0xc0, 0xc4, 0xce, 0x8a,
      0x3d, 0x3b, 0xbd, 0x3a, 0xd5, 0x68, 0x77, 0x92)
    enc = PriceEncoder(e_key, i_key)
    msg = enc.encode(13532120)
    print "encrypt price 13532120: ", msg
    price = enc.decode(msg)
    print "decrypt price 13532120: ", price
    print "decrypt price 709959680:", enc.decode('SjpvRwAB4kB7jEpgW5IA8p73ew9ic6VZpFsPnA')
