import struct
import operator
import collections
import string

JSON_EXCEPTIONS_CONSTANTS = ['4000000080000000C','70000001300000000','F0000001E00000000','F0000011E00000101','3000000020000000100000000','BF000000800000008F00000080','BF000000800000009F00000080','BF00000080000000BF00000080','BF00000080000000BF00000090','BF00000080000000BF000000A0']

STRINGS = []

def insr_to_map(addr, s):

	global MAP
	if addr not in MAP:
		MAP[addr] = []

	MAP[addr].append(s)


MAP = {
	
}

def bnot(n, numbits=8):
	return (1 << numbits) - 1 - n

"""
Thanks to our lord savior:
https://stackoverflow.com/questions/27506474/how-to-byte-swap-a-32-bit-integer-in-python
"""
def swap32(i):
    return struct.unpack("<I", struct.pack(">I", i))[0]


def get_arr(d, length, swap=False):

	barr = bytearray()
	data = collections.OrderedDict(sorted(d.items() , key=operator.itemgetter(0), reverse=True))

	for key, value in data.iteritems():
		if isinstance(value, bytes):
			barr.extend(value)
		elif isinstance(value, int) or isinstance(value, long) :
			if not swap:
				barr.append(value)
			else:
				val = swap32(value)
				val = struct.unpack("=4c", struct.pack(">I", val))
				barr.extend(val)

	return barr


"""
Function to decrypt the strings using a combination of NOT and XOR.
In some samples, there is a bitwise NOT operation in the constant 
used during the decryption phase. Also, the decryption start from
offset 1 instead of 0, so we ended up having:
	- 'flag' parameter, indicating whether a bitwise NOT happened
	- 'off' paramter, which is used to calculate the offset during
	   decryption
	- 'swap' parameter indicating whether we need to swap the constant
	   as during execution they are saved in Little Endian format. 
"""
def decrypt(data, length, constant, off, ea, swap=False, flag=False, log=False):

	# Get a bytearray from the dictionary with reverse order in order
	# emulate the way that the data is stored in memory
	arr = get_arr(data, length, swap=swap)
	if len(arr) - off < length:
		print "[-] There seems to be a problem during decryption of 0x%08x" % ea
		return ""

	# Original index variable
	idx = 0
	"""
	This is a check derived from covering multiple patterns with only one
	function. Sometimes, the constant is not assigned indepentely but 
	rather exist as the first element in the array to be decrypted.
	"""
	if constant == 0:
		constant = arr[0]

	# Decryption routine - combination of NOT and XOR
	while idx < length:
		# Using the off parameter as some patterns prefer to start from pos 1.
		if flag:
			arr[idx + off] ^= bnot(constant,8)
		else:
			arr[idx + off] ^= constant
		
		# Some patterns need re-assigment of the constant
		if off != 0:
			constant = arr[0]
		
		idx += 1

	s = ''.join(chr(x) for x in arr[off:length+off]).rstrip('\0')
	return s


"""
Thanks to https://unit42.paloaltonetworks.com/using-idapython-to-make-your-life-easier-part-5/
"""
def find_string_occurrences(string):
  results = []
  base = idaapi.get_imagebase()
  while True:
    ea = FindBinary(base, SEARCH_NEXT|SEARCH_DOWN|SEARCH_CASE, '%s' % string)
    if ea != 0xFFFFFFFF:
      base = ea+1
    else:
      break 
    results.append(ea)
  return results


"""
Lazy way of detecting whether the MOV instruction is in our interest
"""
def is_valid_assigment(addr):
	op = GetOpnd(addr, 0)

	if "exception" in GetOpnd(addr, 1) or "offset" in GetOpnd(addr, 1):
		return False

	if "word ptr [ebp-" in op or "[ebp+" in op or "[esp+":
		return True

	return False



"""
Function responsible for extracting the offset from instructions like:
	- mov xmmword ptr [ebp+var_, XXXX
	- xmmword ptr [ebp-, XXX
	- dword ptr [ebp-, XXX
	- byte ptr [ebp-, XXX
	- word ptr [ebp-, XXX
	- [ebp+var_, XXX
	- [ebp-, XXX
	- [esp+], XXX
The offset is later used in a dictionary in order to store the data that
would be later used to decrypt the string.
"""
def extract_offset(ea):

	opnd = GetOpnd(ea, 0)
	val = 0

	"""
	Because word ptr [ebp- is a substring to
		- xmmword ptr [ebp-
		- dword ptr [ebp-
		- word ptr [ebp-
	we had some problems during parsing, so there is a check to the first 
	character in order to determine the what to substract and replace in
	order to properly parse the offset.
	"""
	if "x" == opnd[0]:
		if "xmmword ptr [ebp+var_" in opnd:
			try:
				val = int(opnd.replace("xmmword ptr [ebp+var_","").replace("]",""),16)
			except Exception:
				val = None
			return val
		if "xmmword ptr [ebp-" in opnd:
			try:
				val = int(opnd.replace("xmmword ptr [ebp-","").replace("h]",""),16)
			except Exception:
				val = None
			return val

	if "d" == opnd[0]:
		if "dword ptr [ebp-" in opnd:
			try:
				val = int(opnd.replace("dword ptr [ebp-","").replace("h]",""),16)
			except Exception:
				val = None
			return val

	if "b" == opnd[0]:
		if "byte ptr [ebp-" in opnd:
			try:
				val = int(opnd.replace("byte ptr [ebp-","").replace("h]",""),16)
			except Exception:
				val = None
			return val
	if "w" == opnd[0]:
		if "word ptr [ebp-" in opnd:
			try:
				val = int(opnd.replace("word ptr [ebp-","").replace("h]",""),16)
			except Exception:
				val = None
			return val
	if "[" == opnd[0]:
		if "[ebp+var_" in opnd:
			try:
				val = int(opnd.replace("[ebp+var_","").replace("]",""),16)
			except Exception:
				val = None
			return val
		if "[ebp-" in opnd:
			try:
				val = int(opnd.replace("[ebp-","").replace("h]",""),16)
			except Exception:
				val = None
			return val

		if "[esp+" in opnd:
			try:
				arr = opnd.replace('[esp+','').replace("h","").replace(']','').replace('var_','').split('+')
				val = 0
				for n in arr:
					val += int(n,16)
			except Exception:
				val = None
			return val
	return val

"""
Function responsible for associating data with an offset.
The data can be either:
	- x/4/2/1(byte) number references by multiple ways
	- a byte array
It silently fails when 
"""

def insr_to_dict(d, ea, value=None):

	# Get the offset used in a mov [ebp|esp(+|-)], XXX 
	val = extract_offset(ea)
	# XXX Value that would be copied to the aforementioned address.
	opnd = GetOpnd(ea, 1)

	if val is not None and val not in d:
		# Special case with the mov(aps|up) instructions
		if "xmm0" in opnd or value is not None:
			d[val] = value
		else:
			# Generic case - try to parse the value, and silently fail if can't.
			try:
				n = int(opnd.replace('h',""), 16)
				d[val] = n
			except Exception:
				pass
	
	return d


"""
Checks if the constant is equal with a constant used by the JSON
parsing library.
"""
def is_excp_cons(s):
	hs = [elem.encode("hex") for elem in s]
	hs.reverse()
	ns = "".join(hs).lstrip('0')
	return ns.upper() in JSON_EXCEPTIONS_CONSTANTS

"""
Function to parse HEX numbers mostly used by MOV MEM, Value instructions.
"""
def parse_hex(addr, idx):
	n = 0
	try:
		n = int(GetOpnd(addr,idx).replace("h",""),16)
	except Exception:
		n = 0
	return n


def find_string(addr, log=False):
	# Save address that the OPCODE Pattern was matched to.
	start_addr = addr
	# Dictionary holding the data for decryption
	data = {}
	# Length of the string
	length = 0
	# Constant used during the XOR decryption
	constant = 0
	# Variable indicating whether a bitwise NOT operation happened
	flag = False
	# Variable holding the 128bit address.
	xmm0 = 0
	# Address that the decrypted string will be put as comment.
	com = 0
	mnem = GetMnem(addr) 
	while True:
		if mnem == "mov" and GetOpnd(addr, 0) == "cl" and "[" not in GetOpnd(addr, 1):
			constant = parse_hex(addr,1)
		if mnem == "mov" and is_valid_assigment(addr):
			insr_to_dict(data,addr)
		if mnem == "movaps" and GetOpnd(addr, 0) == "xmm0":
			"""
			Unique case of handling 128bit constants. Have to check
			if they belong to the JSON library used by the sample.
			"""
			v = GetOpnd(addr, 1)
			v = int(v.replace('ds:xmmword_',''),16)
			s = GetManyBytes(v,16)
			if is_excp_cons(s):
				print "[-] We are inside JSON library at 0x%08x!" % addr
				return
			xmm0 = s
		if mnem == "not":
			flag = True
		if mnem == "movups":
			insr_to_dict(data, addr, xmm0)
			xmm0 = 0
		if mnem == "cmp":
			length = parse_hex(addr,1)
			a = idc.NextHead(addr)
			mnem = GetMnem(a)
			if mnem == "jnb" or mnem == "jb":
				com = a
				break

		addr = idc.NextHead(addr)
		mnem = GetMnem(addr)

	s = decrypt(data, length, constant, 1, start_addr, swap=True, flag=flag)
	insr_to_map(com, s)
	return addr



"""
Function handling data that is XORed before the final decryption phase.
An example of this pattern is the following:
	- The temporary XOR byte is being pushed
	  push    63h
	- The XOR constant's address is saved in ECX
	  lea     ecx, [ebp-0FDh]
	- The XOR constant is assigned a value
	  mov     byte ptr [ebp-0FDh], 55h
	- The Bitwise XOR/NOT operation takes place
	  call    sub_42D928
	- Step 1, 2 repeated
	  push    6Fh
	  lea     ecx, [ebp-0FDh]
	- The result from the bitwise XOR/NOT is saved
	  mov     [ebp-0FCh], al
"""
def find_string_1(addr, log=False):
	# Save address that the OPCODE Pattern was matched to.
	start_addr = addr
	# Dictionary holding the data for decryption
	data = {}
	# Length of the string
	length = 0
	# Constant used during the XOR decryption
	constant = 0
	# Constant that will be used in XOR operation
	cur_xor = 0
	addr_constant = 0
	res = 0
	is_in_loop = False

	registers = {}

	res_reg = None
	res_reg_val = 0

	mnem = GetMnem(addr)
	com = 0
	while True:
		"""
		Check and saved the address of the constant that will be used later
		in the bitwise XOR/NOT operation. The address is necessary in order 
		to later determine constant's value.
		"""
		opnd = GetOpnd(addr,1)
		if mnem == "lea":
			if GetOpnd(addr,0) == "ecx":
				addr_constant = opnd

		"""
		I suppose this is a compiler optimization? - In some cases, when a
		number would be used multiple times, is being saved to a register.
		"""
		if mnem == "pop":
			res_reg =  GetOpnd(addr,0)
			prev_addr = PrevHead(addr)
			if GetMnem(prev_addr) == "push":
				if res_reg not in registers:
					registers[res_reg] = 0
				# Parse the value
				registers[res_reg] = parse_hex(prev_addr,0)

		if mnem == "push":
			"""
			Because there are cases of resuable bytes, instead of the usual
			push 0xXX instructions, we might have push REG(EBX, EDX etc etc).
			So, we try to distinct the cases and determine the correct value
			for the temporary XOR operand.
			"""
			target = GetOpnd(addr,0)
			if target in registers:
				cur_xor = registers[target]
			elif not is_in_loop:
				cur_xor = parse_hex(addr,0)
		# Lazy and bad check to determine if bitwise XOR/NOT operation is 
		# taken place.
		if mnem == "call":
			res = cur_xor ^ constant
		if mnem == "mov":
			"""
			The results of the XOR/NOT operations are saved, so we try to
			extract the offset and associate it with a value in our dictionary.
			"""
			if addr_constant in GetOpnd(addr,0):
				constant = parse_hex(addr,1)
			if opnd == "al":
				off = extract_offset(addr)
				if off > 0 and off not in data:
					data[off] = res
					res = 0
		# Check to determine if we are inside the final decryption phase
		if mnem == "xor":
			is_in_loop = True
		if mnem == "cmp":
			length = parse_hex(addr,1)
			a = idc.NextHead(addr)
			mnem = GetMnem(a)
			if mnem == "jnb" or mnem == "jb":
				com = a
				break

		addr = idc.NextHead(addr)
		mnem = GetMnem(addr)

	s = decrypt(data, length, constant, 0, start_addr, flag=False)
	insr_to_map(com, s)
	return addr
		



FUNCT = {

	"0F 28 05 ?? ?? ?? ??": find_string,
	"C7 45 ?? ?? ?? ?? ??": find_string,
	"C7 45 ?? ?? ?? ?? ?? B1 ??": find_string,
	"C7 ?? ?? ?? ?? ?? ?? ?? B1 ??": find_string,
	"C7 85 ?? ?? FF FF ?? ?? ?? ?? B1 ??": find_string,
	"B1 ?? C7 ?? ?? ?? ?? ?? ??": find_string,
	"B1 ?? C7 85 ?? ?? FF FF ?? ?? ?? ??": find_string,
	"B2 ?? C7 ?? ?? ?? ?? ?? ??": find_string,
	"6A ?? ?? ?? ?? ?? ?? ?? C6 ?? ?? ?? ?? ?? ?? E8": find_string_1,
	"6A ?? 8D ?? ?? ?? ?? ?? 89 ?? ?? C6 ?? ?? ?? ?? ?? ?? E8": find_string_1,
}


'''
FUNCT = {
	#"B1 ?? C7 85 ?? ?? FF FF ?? ?? ?? ??": find_string,
	#"0F 28 05 ?? ?? ?? ??": find_string,
	#"C7 85 ?? ?? FF FF ?? ?? ?? ?? B1 ??": find_string,
	#"C7 45 ?? ?? ?? ?? ?? B1 ??": find_string,
	#//"B1 ?? C7 ?? ?? ?? ?? ?? ??": find_string,
	#"6A ?? ?? ?? ?? ?? ?? ?? C6 ?? ?? ?? ?? ?? ?? E8": find_string_1,
	"B2 ?? C7 ?? ?? ?? ?? ?? ??": find_string,
	#"6A ?? 8D ?? ?? ?? ?? ?? 89 ?? ?? C6 ?? ?? ?? ?? ?? ?? E8": find_string_1,
	#"C7 ?? ?? ?? ?? ?? ?? ?? B1 ??": find_string,

}'''


def is_valid_str(s):

	for c in s:
		c = ord(c)
		if (c < 31 or c > 126) and c != 10:
			return False

	return True


def cmp_str(arr, idx):

	s0 = arr[idx]
	s1 = arr[idx+1]
	if s0 not in s1 and is_valid_str(s0):
		return s0
	elif is_valid_str(s1):
		return s1

	return ''
	
def string_candidate(arr):

	l = len(arr)
	if l == 1:
		return arr[0]

	r = ''
	idx = 0
	arr = sorted(arr)
	while idx < len(arr) - 1:
		r = cmp_str(arr,idx)
		idx += 2

	if l % 2 != 0:
		r = cmp_str(arr,len(arr) - 2)

	return r


def add_comments(d):

	'''
	'''
	m = collections.OrderedDict(sorted(MAP.items() , key=operator.itemgetter(0)))
	for addr, arr in m.iteritems():
		s = string_candidate(arr)
		if s != '':
			STRINGS.append(s)
			h = ''.join('{:02x}'.format(ord(x)) for x in s)
			print "[+] Found string [%s/%s] at address 0x%08x" % (s,h, addr)
			MakeComm(addr,"String is : {0}/{1}".format(s,h))


def search_strings(flag, path=''):

	global STRINGS
	STRINGS = []
	global MAP
	MAP = {}
	for pattern, func in FUNCT.iteritems():
		addr = 0
		eas = find_string_occurrences(pattern)
		print "[++] Found %d instances %s" % (len(eas), pattern)
		for ea in eas:
			if ea < addr:
				continue
			addr = func(ea,log=flag)


	
	add_comments(MAP)

	
	if flag and path != '':
		with open(path, 'w') as f:
			for item in sorted(STRINGS):
				if all(c in string.printable for c in item):
        			f.write("%s\n" % item)
    
	

