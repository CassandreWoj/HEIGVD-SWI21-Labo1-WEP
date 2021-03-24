#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually decrypt a wep message given the WEP key"""

__author__ = "Abraham Rubinstein"
__copyright__ = "Copyright 2017, HEIG-VD"
__license__ = "GPL"
__version__ = "1.0"
__email__ = "abraham.rubinstein@heig-vd.ch"
__status__ = "Prototype"

from scapy.all import *
# import binascii
from rc4 import RC4
import zlib

# Nouveau payload
# w_payload=b"\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x90'\xe4\xeaa\xf2\xc0\xa8\x01d\x00\x00\x00\x00\x00\x00\xc0\xa8\x01\xc8"
new_payload = b"\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x92'\xe4\xeaa\xf2\xc0\xa8\x01d\x00\x00\x00\x00\x00\x00\xc0\xa8\x01\xc8"

# Cle wep AA:AA:AA:AA:AA
key = b'\xaa\xaa\xaa\xaa\xaa'


def ieee_gen(payload, key):
    """
    Chiffre un payload wifi
    @param payload: suite de bytes à chiffrer
    @param key: Clé sous forme de suite de bytes
    @return: le packet créer
    """

    # lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient un seul paquet
    arp = rdpcap('arp.cap')[0]

    # rc4 seed est composé de IV+clé
    seed = arp.iv + key

    # chiffrement rc4
    cipher = RC4(seed, streaming=False)
    icv = zlib.crc32(payload)
    payload_with_icv = payload + icv.to_bytes(4, byteorder='little')
    payload_with_icv = cipher.crypt(payload_with_icv)
    arp.wepdata = payload_with_icv[:-4]
    arp.icv = int.from_bytes(payload_with_icv[-4:], 'big')

    return arp


if __name__ == '__main__':
    packet = ieee_gen(new_payload, key)
    wrpcap("test.cap", packet)
