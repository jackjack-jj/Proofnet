#!/usr/bin/env python3.2

import proofnet
import argparse
import base64

parser=argparse.ArgumentParser(description="Encode text into a base 16 encoded Proofnet message (type proofnet:text).")
parser.add_argument("text", type=str)
parser.add_argument("--nzeros", type=int)
args=parser.parse_args()
pm=proofnet.proof_message_text()
pm.set_text(args.text)
if args.nzeros!=None:
	pm.set_target_nzeros(args.nzeros)
pm.do_work()
print(base64.b16encode(pm.get_bytes()).decode('utf-8'))
