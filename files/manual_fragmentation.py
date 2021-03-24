#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually decrypt a wep message given the WEP key"""

__author__ = "Abraham Rubinstein, Cassandre Wojciechowski, Gabriel Roch"
__copyright__ = "Copyright 2017, 2021, HEIG-VD"
__license__ = "GPL"
__version__ = "1.1"
__email__ = "abraham.rubinstein@heig-vd.ch"
__status__ = "Prototype"

from scapy.all import *
from manual_generator import ieee_gen

# Nouveau payload
# w_payload=b"\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x90'\xe4\xeaa\xf2\xc0\xa8\x01d\x00\x00\x00\x00\x00\x00\xc0\xa8\x01\xc8"
new_payload = b"\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x92'\xe4\xeaa\xf2\xc0\xa8\x01d\x00\x00\x00\x00\x00\x00\xc0\xa8\x01\xc8"

# Cle wep AA:AA:AA:AA:AA
key = b'\xaa\xaa\xaa\xaa\xaa'

nb_fragm = 3
fragements = [0] * nb_fragm
frag_no = 0
for i in range(0, len(new_payload), int(len(new_payload) / nb_fragm)):
    e = int(i + len(new_payload) / nb_fragm)

    # obtient un packet chiffrer pour fragment de payload
    fragements[frag_no] = ieee_gen(new_payload[i:e], key)

    # More fragment = 1
    fragements[frag_no].FCfield |= 0x04

    # Compteur de fragement
    fragements[frag_no].SC = frag_no

    frag_no += 1

# More fragment = 0
fragements[frag_no - 1].FCfield &= ~0x04

wrpcap("test.cap", fragements)
