#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually decrypt a wep message given the WEP key"""

__author__      = "Abraham Rubinstein"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
import binascii
from rc4 import RC4
import zlib

#Nouveau payload
new_payload=b"\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x90'\xe4\xeaa\xf2\xc0\xa8\x01d\x00\x00\x00\x00\x00\x00\xc0\xa8\x01\xc8"
new_payload=b"\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x92'\xe4\xeaa\xf2\xc0\xa8\x01d\x00\x00\x00\x00\x00\x00\xc0\xa8\x01\xc8"

#Cle wep AA:AA:AA:AA:AA
key= b'\xaa\xaa\xaa\xaa\xaa'

#lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient un seul paquet
arp = rdpcap('arp.cap')[0]

# rc4 seed est composé de IV+clé
seed = arp.iv+key

# recuperation de icv dans le message (arp.icv) (en chiffre) -- je passe au format "text". Il y a d'autres manières de faire ceci...
icv_encrypted='{:x}'.format(arp.icv)

# text chiffré y-compris l'icv
message_encrypted=arp.wepdata+bytes.fromhex(icv_encrypted)



# déchiffrement rc4
cipher = RC4(seed, streaming=False)
icv_pre_calc = zlib.crc32(new_payload)
# new_full_payload = new_payload+icv_pre_calc.to_bytes(4, byteorder='little');
# new_full_payload = cipher.crypt(new_full_payload)


nb_fragm = 2
fragements = [0] * nb_fragm
frag_no = 0
print(len(new_payload)/nb_fragm)
for i in range(0, len(new_payload), int(len(new_payload)/nb_fragm)):
    e = int(i+len(new_payload)/nb_fragm)
    fragment_payload = new_payload[i:e]

    arp.FCfield |= 0x04
    icv_pre_calc = zlib.crc32(fragment_payload)
    new_fragment_payload = fragment_payload + icv_pre_calc.to_bytes(4, byteorder='little');
    new_fragment_payload = cipher.crypt(new_fragment_payload)
    arp.wepdata = new_fragment_payload[:-4]
    arp.icv = int.from_bytes(new_fragment_payload[-4:], 'big')
    # print(frag_no)
    print(hex(int.from_bytes(new_fragment_payload[:-4], byteorder='big')),
          hex(int.from_bytes(new_fragment_payload[-4:], byteorder='big')))
    fragements[frag_no] = arp.copy()
    frag_no += 1
    arp.SC += 1

    pass
# print(len(new_full_payload) / 4)
fragements[nb_fragm-1].FCfield &= ~0x04

# Passé au fragement suivant
arp.SC += 0

# Définit le bit more fragment à 1
arp.FCfield |= 0x04;


# arp.wepdata = new_full_payload[:-4]
# arp.icv = int.from_bytes(new_full_payload[-4:], 'big');
# cleartext = cipher.crypt(message_encrypted)
#
# le ICV est les derniers 4 octets - je le passe en format Long big endian
# icv_enclair=cleartext[-4:]
# print(zlib.crc32(cleartext[:-4]).to_bytes(4, byteorder='little'))

# le message sans le ICV
# text_enclair=cleartext[:-4]


wrpcap("test.cap", fragements);
# wrpcap("test.cap", [arp, arp]);
