import csv
import random
import hmac
import hashlib




KEYS = []
ROUNDS = 4
STEP = 256

def init_keys():
	global KEYS
	try:
		with open('keys.bin', newline='') as csvfile:
			spamreader = csv.reader(csvfile, delimiter=' ', quotechar='|')
			for row in spamreader:
				KEYS = [int(key) for key in row]
	except:
		KEYS = [random.randint(1, 1024) for _ in range(ROUNDS)]
		with open('keys.bin', 'w', newline='') as csvfile:
			writer = csv.writer(csvfile, delimiter=' ',
									quotechar='|', quoting=csv.QUOTE_MINIMAL)
			writer.writerow(KEYS)

def binary_xor(a, b):
	a_bin = ''.join('{:08b}'.format(x) for x in bytearray(a.encode('utf-8')))
	b_bin = ''.join('{:08b}'.format(x) for x in bytearray(b.encode('utf-8')))
	out = [(ord(x1) ^ ord(x2)) for x1,x2 in zip(a, b)]

	return ''.join([chr(x) for x in out])

def feistel(keys, data, mode="encode"):
	if mode == "decode":
		keys = keys[::-1]
	l = data[:int(len(data)/2)]
	r = data[int(len(data)/2):]

	for key in keys:
		key = bytearray(key)
		r_hash = hmac.new(key, msg=r.encode('utf-8'), digestmod=hashlib.sha256).hexdigest()
		l, r = r, binary_xor(l, r_hash)
	return r + l

def encode_text():
	init_keys()

	filename = "input.txt"
	global STEP
	# Open file
	plain_file = open(filename, "r+")
	cipher_file = open("cipher.bin", "w")

	# Read all lines in the file
	byte_step = int(STEP/8)

	eof = False
	line = bytearray(plain_file.readline().encode("utf-8"))
	while not eof:
		if len(line) < byte_step:
			temp_line = bytearray(plain_file.readline().encode("utf-8"))
			while len(line) < byte_step and len(temp_line) != 0:
				line += temp_line
				temp_line = bytearray(plain_file.readline().encode("utf-8"))
			if len(line) < byte_step:
				line = line + bytearray([0] * (byte_step-len(line)))
				eof = True

		line_seg = line[:byte_step]
		del line[:byte_step]
		print(f"============================================================================")
		encoded = feistel(KEYS, str(line_seg), mode="encode").encode('unicode_escape')
		print(f"PLAIN: {str(line_seg)}")
		print(f"ENCODED: {encoded}")
		print(f"DECODED: {feistel(KEYS, encoded.decode('unicode-escape'), mode='decode')}")
		print(f"============================================================================")
		
		# print(''.join('{:02x}'.format(x) for x in line_seg) + "\t" + str(line_seg))
		# print(encoded.encode('unicode_escape').decode(), end=f"\n{'-'*100}\n")
		
	# encoded = feistel(KEYS, "Hello World!", mode="encode").encode('unicode_escape')
	# print(encoded)
	# print(feistel(KEYS, encoded.decode('unicode-escape'), mode="decode"))

encode_text()
