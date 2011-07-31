#!/usr/bin/env python3.2

import proofnet
import argparse
import base64

parser=argparse.ArgumentParser(description="Decode text from a base 16 encoded Proofnet message (type proofnet:text)")
parser.add_argument("b16encoded", type=str)
args=parser.parse_args()
pm=proofnet.proof_message_text()
mybytes=base64.b16decode(args.b16encoded.encode())
pm.decode_from_bytes(mybytes)
print(pm.get_text())
