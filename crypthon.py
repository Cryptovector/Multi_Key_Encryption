import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import constant_time, hashes, hmac
from cryptography.hazmat.backends import default_backend
backend = default_backend()
Segmentlog = 20
Segmentlength = 1048576


def encrypt_file(Fileheader, key, in_filename, out_filename=None):
	
	if not out_filename:
		out_filename = in_filename + '.enc'

	Key_Hash = hashes.Hash(hashes.SHA256(), backend=default_backend())	
	Key_Hash.update(key)
	Data = 	Key_Hash.finalize()
	in_file = open(in_filename, "rb")
	Filesize = os.path.getsize(in_filename) 

	iv = os.urandom(16)
	cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
	HMAC = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
	encryptor = cipher.encryptor()

	HMAC.update(iv)
	Paddinglength = (15 - (Filesize % 16)) #(16 - len(File_Data) % 16)
	Padding = bytearray(Paddinglength) + bytes([Paddinglength])

	with open(out_filename, 'wb') as outfile:
		outfile.write(Fileheader)
		outfile.seek(80+len(Fileheader))

		for i in range(Filesize>>Segmentlog):
			Segment = in_file.read(Segmentlength)
			HMAC.update(Segment)
			outfile.write(encryptor.update(Segment))		

		for i in range((Filesize&(Segmentlength-1))>>4):
			Segment = in_file.read(16)
			HMAC.update(Segment)
			outfile.write(encryptor.update(Segment))

		Segment = in_file.read(16)+Padding
		HMAC.update(Segment)
		outfile.write(encryptor.update(Segment))
		outfile.seek(len(Fileheader)) #(0)
		outfile.write(Data+HMAC.finalize()+iv)

	print("---Encryption Complete---")  	


def decrypt_file(key, in_filename, out_filename=None):

	if not out_filename:
		out_filename = os.path.splitext(in_filename)[0]
	
	in_file = open(in_filename, "rb") 
	File_Data = in_file.read(80)
	Filesize = os.path.getsize(in_filename)

	Data = File_Data[0:32]
	AC = File_Data[32:64]
	iv = File_Data[64:80]
	
	Key_Hash = hashes.Hash(hashes.SHA256(), backend=default_backend())	
	Key_Hash.update(key)
	if not Key_Hash.finalize() == Data:
		return 0

	cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
	HMAC = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
	decryptor = cipher.decryptor()

	HMAC.update(iv)
	with open(out_filename, 'wb') as outfile:

		for i in range((Filesize-80)>>Segmentlog):
			Segment = in_file.read(Segmentlength)
			Segment = decryptor.update(Segment)	
			outfile.write(Segment)
			HMAC.update(Segment)

		for i in range(((Filesize&(Segmentlength-1))>>4)-6):
			Segment = in_file.read(16)
			Segment = decryptor.update(Segment)	
			outfile.write(Segment)
			HMAC.update(Segment)
		
		Segment = in_file.read(16)
		Segment = decryptor.update(Segment)
		HMAC.update(Segment)
		outfile.write(Segment[0:0-(Segment[-1]+1)])
	
	in_file.close()
	decryptor.finalize()	
	HMAC.verify(AC)	

	print("---Decryption Complete---")