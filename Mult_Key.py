import os, sys, argparse
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import constant_time, hashes, hmac
from cryptography.hazmat.backends import default_backend
import math
import Math_func
import crypthon
backend = default_backend()

Modulus = 2**256-189 
Maxkeylength = 256 #Must be 2**x
Maxkeylength_2 = Maxkeylength*Maxkeylength

def Gen_Scrypt_Instance(salt):
	kdf = Scrypt(
		salt=salt,
		length=32,
		n=2**16,
		r=8,
		p=1,
		backend=backend
	)
	return kdf

def Generate_Key_Scrypt(Key): 
	salt = os.urandom(16)
	kdf = Gen_Scrypt_Instance(salt)
	Der_Key = kdf.derive(Key)
	Der_Key_Hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
	Der_Key_Hash.update(Der_Key)
	print("----Key derivation on Encryption Complete----")
	return (salt + Der_Key_Hash.finalize()), Der_Key

def Decrypt_Key_Scrypt(salt, Hash, Key):
	kdf = Gen_Scrypt_Instance(salt)
	Der_Key = kdf.derive(Key)
	Der_Key_Hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
	Der_Key_Hash.update(Der_Key)
	if constant_time.bytes_eq(Hash, Der_Key_Hash.finalize()):
		print("----Key derivation on Decryption Complete----")
		return Der_Key
	else:
		return 0

def Decrypt_File(Offset, Key, filepath):
	out_filename = os.path.splitext(filepath)[0]+'.tmp'

	with open(out_filename, 'ab') as outfile:
		with open(filepath, 'rb') as readfile:
			readfile.seek(Offset)
			while True:
				Data = readfile.read(1024)
				if not len(Data):
					break
				outfile.write(Data)

	Decr = crypthon.decrypt_file(Key, out_filename)
	os.remove(out_filename)
	if Decr == 0:
		return 0
	else:
		return 1

def Rec_Masterkey(length, Index_list, Seed, Out_vector):
	Gauss = Math_func.Gauss_Matrix(length, length, Modulus)
	subgproup = []
	for i in range(length):
		subgproup.append(Index_list[i])

	Gauss.Generate_inv_Matrix(Seed, subgproup)
	Gauss.Gaussian_Elimation_Modulo()
	Rec_Vector = Gauss.Vector_Rec(Out_vector)

	Master_Hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
	for i in range(length):
		Master_Hash.update(Rec_Vector[i].to_bytes(32, byteorder='big'))
	Masterkey = Master_Hash.finalize()

	return Masterkey

def Dec_Index(Der_Key, Salt, Encrypted_dataset):
	cipher = Cipher(algorithms.AES(Der_Key), modes.CBC(Salt), backend=backend)
	decryptor = cipher.decryptor()
	dataset = decryptor.update(Encrypted_dataset)
	decryptor.finalize()
	return dataset

def Generate_Index(Salt, Key):
	kdf = Gen_Scrypt_Instance(Salt)
	return int.from_bytes(kdf.derive(Key), byteorder='big')&(Maxkeylength_2-1)

def Create_System(filepath, out_filename=None):

	if out_filename == None:
		out_filename = filepath+'.enc'

	print("Should the System store Metadata ?")
	print("1. Full Metadata: Show's Keys_needet/keys and shows Incorrect Key inputs | File is recognisable as Encrypted Dataset")
	print("2. Less Metadata: Show's Keys_needet/keys and shows Incorrect Key inputs after 1 Correct key is given | File is recognisable as Encrypted Dataset with one known Key")
	print("3. No Metadata: Show's nothing (This includes Incorrect Key inputs) | File is indistinguishable from Random Data without the Correct Number of keys")
	print("Type a number ...")
	while True:
		Metadata = int(input())
		if 0 < Metadata < 4:
			break
		else:
			print("Data invalid ... please try again")

	print("How many Keys should the System have ?")
	while True:
		Keycount = int(input())
		if Keycount > Maxkeylength | Keycount == 0:
			print("Maximum is 256 Keys | Minimum 1")
		else:
			break
	print("How many Keys are needet for Decryption ?")
	while True:
		Needkeys = int(input())
		if Needkeys > Keycount | Needkeys == 0:
			print("Needkeys can not be greater than Keycount | Needkeys must be greater than 0")
		else:
			break

	print("Would you like to Double type Keys (If you make a mistake by Keyboard input) Y/N?")
	Doublekey = input()
	if Doublekey == "Y":
		Doublekey = True
	else:
		Doublekey = False

	Keylist = []
	while len(Keylist) < Keycount:
		print("Please type key: "+str(len(Keylist)+1)+" of "+str(Keycount))
		Tmpkey = input()
		if Doublekey:
			print("Please type key again.")
			if Tmpkey == input():
				Keylist.append(Tmpkey)
			else:
				print("Please try again ... (Your Input does not Match)")
		else:
			Keylist.append(Tmpkey)

	if Metadata == 3:
		if len(Keylist) > len(set(Keylist)): #Must be
			print("Keys for Metadata Mode 3 must be unique ... 1 or more Keys are not unique please try again")
			return 0
		Matlength = Maxkeylength_2
	else:
		Matlength = Keycount

	print("Thank you ... creating System")

	Der_Keylist = []
	for i in range(Keycount):
		if Metadata < 3:
			Der_Keylist.append(Generate_Key_Scrypt(Keylist[i].encode('utf-8')))
		else:
			salt = os.urandom(16)
			kdf = Gen_Scrypt_Instance(salt)
			Der_Key = kdf.derive(Keylist[i].encode('utf-8'))
			Der_Keylist.append([salt, Der_Key])

	Key_vector = []
	Master_Hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
	for i in range(Needkeys):
		Key_vector.append((int.from_bytes(os.urandom(32), byteorder='big')%Modulus-1)+1)
		Master_Hash.update(Key_vector[-1].to_bytes(32, byteorder='big'))

	Masterkey = Master_Hash.finalize()
	Gauss_Matrix = Math_func.Gauss_Matrix(Matlength, Needkeys, Modulus)
	Seed = os.urandom(32)
	Gauss_Matrix.Generate_Matrix(Seed, [i for i in range(Matlength)])
	Out_vector = Gauss_Matrix.Vector_Matrix_Multiplication(Key_vector)

	Fileheader = bytearray()
	Fileheader += Seed
	if Metadata == 1:
		Fileheader += bytes([Keycount-1])
		Fileheader += bytes([Needkeys-1])

	if Metadata == 3:
		while True: 
			Salt = os.urandom(16)
			Keyindex = {}
			print("Try Generating Salt for unique Index assignment")
			for i in range(Keycount):
				Index = Generate_Index(Salt, Keylist[i].encode('utf-8'))
				if Index in Keyindex:
					break
				else:
					Keyindex[Index] = i

			if len(Keyindex) == Keycount:
				break

		Fileheader += Salt

		for i in range(Matlength):
			if i in Keyindex:
				Fileheader += Der_Keylist[Keyindex[i]][0]
				cipher = Cipher(algorithms.AES(Der_Keylist[Keyindex[i]][1]), modes.CBC(Der_Keylist[Keyindex[i]][0]), backend=backend)
				encryptor = cipher.encryptor()
				Fileheader += encryptor.update(Out_vector[i].to_bytes(32, byteorder='big'))
				encryptor.finalize()
			else:
				Fileheader += os.urandom(48)
	else:

		for i in range(Keycount):
			Fileheader += Der_Keylist[i][0]
			cipher = Cipher(algorithms.AES(Der_Keylist[i][1]), modes.CBC(Der_Keylist[i][0][:16]), backend=backend)
			encryptor = cipher.encryptor()
			Fileheader += encryptor.update(Out_vector[i].to_bytes(32, byteorder='big'))
			if Metadata == 2:
				Fileheader += encryptor.update(bytes([Keycount-1])+bytes([Needkeys-1])+os.urandom(14))
			encryptor.finalize()

	crypthon.encrypt_file(Fileheader, Masterkey, filepath, out_filename)


def Decrypt_System(filepath, out_filename=None):

	if not out_filename:
		out_filename = os.path.splitext(filepath)[0]

	print("What type of metadata was used to create the file ?")
	print("1. Full Metadata: Show's Keys_needet/keys and shows Incorrect Key inputs | File is recognisable as Encrypted Dataset")
	print("2. Less Metadata: Show's Keys_needet/keys and shows Incorrect Key inputs after 1 Correct key is given | File is recognisable as Encrypted Dataset with one known Key")
	print("3. No Metadata: Show's nothing (This includes Incorrect Key inputs) | File is indistinguishable from Random Data without the Correct Number of keys")
	print("Type a number ...")
	while True:
		Metadata = int(input())
		if 0 < Metadata < 4:
			break
		else:
			print("Data invalid ... please try again")

	if Metadata == 3:
		print("Would you like to Double type Keys (If you make a mistake by Keyboard input) Y/N?")
		Doublekey = input()
		if Doublekey == "Y":
			Doublekey = True
		else:
			Doublekey = False

	Offset = 32
	Keylist = []
	Out_vector = []
	Index_list = {}
	Rev_Index = {}
	Masterkey = None
	Seed = None
	Keycount = None
	Needkeys = None
	Filesize = os.path.getsize(filepath)

	with open(filepath, 'rb') as readfile:
		Seed = readfile.read(32)

	if Metadata < 3:

		if Metadata == 1:
			with open(filepath, 'rb') as readfile:
				readfile.seek(Offset)
				Keycount = int.from_bytes(readfile.read(1), byteorder='big')+1
				Needkeys = int.from_bytes(readfile.read(1), byteorder='big')+1
			Matlength = Keycount
			Offset += 2

		else:
			Maxkeys = math.ceil(Filesize/96)
			if Maxkeys > Maxkeylength:
				Maxkeys = Maxkeylength

			while True:
				print("Please type key: "+str(len(Keylist)+1)+" of "+str(Keycount))
				Tmpkey = str(input())
				for i in range(Maxkeys): #Filesize
					with open(filepath, 'rb') as readfile:
						readfile.seek(96*i+Offset)
						Salt = readfile.read(16)
						Key_Hash = readfile.read(32)
						Encrypted_dataset = readfile.read(48)
						Der_Key = Decrypt_Key_Scrypt(Salt, Key_Hash, Tmpkey.encode('utf-8'))
					if Der_Key:	
						dataset = Dec_Index(Der_Key, Salt, Encrypted_dataset)
						Keycount = int.from_bytes(dataset[32:33], byteorder='big')+1
						Needkeys = int.from_bytes(dataset[33:34], byteorder='big')+1
						Out_vector.append(int.from_bytes(dataset[:32], byteorder='big'))
						Index_list[0] = i
						Rev_Index[i] = None
						break

				if len(Out_vector):
					print("Key Correct | Decrypted Metadata")
					break

		if Metadata == 1:
			if (Keycount < Needkeys) | ((Keycount*80) > (Filesize-2)):
				print("File is too short or Metadata error")
				return 0
		else:
			if (Keycount < Needkeys) | (Keycount > Maxkeys):
				print("File is too short or Metadata error")
				return 0		

		while len(Out_vector) < Needkeys:
			print("Please type key: "+str(len(Out_vector)+1)+" of "+str(Keycount))
			Tmpkey = str(input())
			Len_vec = len(Out_vector)
			for i in range(Keycount):
				if not i in Rev_Index:
					with open(filepath, 'rb') as readfile:
						if Metadata == 2:
							readfile.seek(96*i+Offset)
						else:
							readfile.seek(80*i+Offset)
						Salt = readfile.read(16)
						Key_Hash = readfile.read(32)
						if Metadata == 2:
							Encrypted_dataset = readfile.read(48)
						else:
							Encrypted_dataset = readfile.read(32)
						Der_Key = Decrypt_Key_Scrypt(Salt, Key_Hash, Tmpkey.encode('utf-8'))

					if Der_Key:
						dataset = Dec_Index(Der_Key, Salt, Encrypted_dataset)
						Out_vector.append(int.from_bytes(dataset[:32], byteorder='big'))
						Index_list[len(Out_vector)-1] = i
						Rev_Index[i] = None
						print("Key Correct")
						break

			if (Len_vec+1)!=len(Out_vector):
				print("Key Incorrect")

		Masterkey = Rec_Masterkey(Needkeys, Index_list, Seed, Out_vector)

		if Metadata == 2:
			Offset += Keycount*96
		else:
			Offset += Keycount*80

		if Decrypt_File(Offset, Masterkey, filepath):
			print("Successfull Decryption")
		else:
			print("Decryption Failed")
	else:

		if Filesize < ((Maxkeylength_2*48)+16):
			print("File is too short")
			return 0

		with open(filepath, 'rb') as readfile:
			readfile.seek(Offset)
			Salt = readfile.read(16)
			Offset += 16

		while True:
			print("Please type key: "+str(len(Keylist)+1)+" of "+str(Keycount))
			Tmpkey = input()
			if Doublekey:
				print("Please type key again.")
				if Tmpkey == input():
					Keylist.append(Tmpkey)
				else:
					print("Please try again ... (Your Input does not Match)")
			else:
				Keylist.append(Tmpkey)

			print("Would you like to Decrypt the System (To decrypt the System all Keys must be Correct and the Number of Keys must equal the Needkey Parameter)? Y/N")
			Answer = str(input())
			if Answer == 'Y':
				print("Thank you ... Try to decrypt System")
				print("Try Generating unique Index assignment")
				Index_list = []
				for y in range(len(Keylist)):
					Index_list.append(Generate_Index(Salt, Keylist[y].encode('utf-8')))

				for y in range(len(Index_list)):
					with open(filepath, 'rb') as readfile:
						readfile.seek(48*Index_list[y]+Offset)
						Salt = readfile.read(16)
						Encrypted_dataset = readfile.read(32)
						kdf = Gen_Scrypt_Instance(Salt)
						Der_Key = kdf.derive(Keylist[y].encode('utf-8'))
						dataset = Dec_Index(Der_Key, Salt, Encrypted_dataset)
						Out_vector.append(int.from_bytes(dataset, byteorder='big'))

				Masterkey = Rec_Masterkey(len(Keylist), Index_list, Seed, Out_vector)

				if Decrypt_File(Offset+(Maxkeylength_2*48), Masterkey, filepath):
					print("Successfull Decryption")
					return 0

				print("Decryption Failed")
			else:
				if len(Keylist) > Maxkeylength:
					print("Too many Keys ... Programm will Exit now")
					return 0
				else:
					print("Please Type more Keys or Exit the Programm")


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Multi Key de_encryption')
	parser.add_argument('-e','--encrypt', action='store_false')
	parser.add_argument('-d','--decrypt', action='store_false')
	parser.add_argument('-f', '--file',
			action="store", dest="filepath",
			help="File to De and Encrypt", default="", required=True)
	parser.add_argument('-o', '--outfile',
			action="store", dest="outfilepath",
			help="File to write Processed Data", default="")

	args = parser.parse_args()

	if (args.decrypt ^ args.encrypt):

		Outfile = None
		if not args.outfilepath == "":
			Outfile = args.outfilepath

		if not args.encrypt:
			Create_System(args.filepath, Outfile)
		if not args.decrypt:
			Decrypt_System(args.filepath, Outfile)
	else:
		print("Usage: use -d or -e")