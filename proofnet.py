import struct
import hashlib
import time

known_hash_strings=[\
		"proofnet",\
		"proofnet.1",\
		"proofnet.2",\
		"proofnet.3",\
		"proofnet.4",\
		"proofnet.5",\
		"proofnet:text",\
		"proofnet:textfrom",\
		"proofnet:textto",\
		"proofnet:encrypted",\
		]

known_hashes={}

for string in known_hash_strings:
	known_hashes[hashlib.sha256(string.encode()).digest()]=string

def invert_hash(hashbytes):
	try:
		inverted=known_hashes[hashbytes]
	except KeyError:
		return False
	return inverted

def is_hash_less(test_hash_bytes, target_bytes):
	"""test_hash_bytes and target_bytes must be bytes, and same length.
	unlike x86 integers, we assume big endian
	"""
	for i in range(0,32):
		if test_hash_bytes[i]<target_bytes[i]:
			return True
		if test_hash_bytes[i]>target_bytes[i]:
			return False
	return False

#message format in bytes:
#(proof hash)(nonce)(utc time)(channel hash)(message type hash)(message)
class proof_message:
	def __init__(self):
		self.target=b"\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
		self.proof_hash=bytes()
		self.nonce=0
		self.utc_time=time.time()
		self.channel=""
		self.channel_hash=bytes()
		self.message_type=""
		self.message_type_hash=bytes()
		self.message=bytes()

	def decode_from_bytes(self, pmbytes):
		assert len(pmbytes)>=32+8+8+32+32,\
				"Message too short to be a proofnet message"
		self.proof_hash=pmbytes[0:32]
		self.nonce=struct.unpack("L",pmbytes[32:32+8])[0]
		self.utc_time=float(struct.unpack("L",pmbytes[32+8:32+8+8])[0])
		self.channel_hash=pmbytes[32+8+8:32+8+8+32]
		self.channel=invert_hash(self.channel_hash)
		self.message_type_hash=pmbytes[32+8+8+32:32+8+8+32+32]
		self.message_type=invert_hash(self.message_type_hash)
		self.message=pmbytes[32+8+8+32+32:len(pmbytes)]
	
	def update_utc_time(self):
		self.utc_time=time.time()
	
	def set_channel(self, channel):
		self.channel=channel
		self.channel_hash=hashlib.sha256(channel.encode()).digest()
	
	def set_message_type(self, message_type):
		self.message_type=message_type
		self.message_type_hash=hashlib.sha256(message_type.encode()).digest()

	def set_message(self, message):
		self.message=message
	
	def get_after_proof_bytes(self):
		b=bytes()
		nonce=int(self.nonce)
		nonce_bytes=struct.pack("L",nonce)
		b+=nonce_bytes
		time=int(self.utc_time)
		time_bytes=struct.pack("L",time)
		b+=time_bytes
		b+=self.channel_hash
		b+=self.message_type_hash
		b+=self.message
		return b

	def is_recent(self):
		if not time.time()-60*10<self.utc_time<time.time()+60*10:
			return False

	def is_proof_hash_correct(self):
		supposed_hash=self.proof_hash
		actual_hash=hashlib.sha256(self.get_after_proof_bytes().digest())
		if supposed_hash!=actual_hash:
			return False
		return True

	def get_bytes(self):
		return self.proof_hash+self.get_after_proof_bytes()

	def calc_proof_hash(self):
		b=self.get_after_proof_bytes()
		proof_hash=hashlib.sha256(b).digest()
		self.proof_hash=proof_hash

	def set_target(self, target_bytes):
		self.target=target_bytes

	def set_target_nzeros(self, nzeros):
		"""nzeros must be integer for now"""
		target=[]
		for i in range(32):
			if nzeros>=8:
				byte=0
				nzeros=nzeros-8
			elif nzeros>0:
				byte=2**(8-nzeros)-1
				nzeros=0
			else:
				byte=255
			target.append(byte)
		target=bytes(target)
		self.target=target

	def get_target_nzeros(self):
		nzeros=0
		for byte in self.target:
			for n in range(8):
				this_nzeros=0
				if byte<2**n:
					this_nzeros+=8-n
					break
			if this_nzeros==0:
				break
			nzeros+=this_nzeros
		return nzeros

	def do_work(self):
		target=self.target
		progress=0
		while 1:
			for nonce in range(0,1000000):
				progress+=1
				self.update_utc_time()
				self.nonce=nonce
				self.calc_proof_hash()
				testhash_bytes=self.proof_hash
				if is_hash_less(testhash_bytes,self.target):
					return progress

class proof_message_text(proof_message):
	def get_text(self):
		return m.encode('utf-8')













