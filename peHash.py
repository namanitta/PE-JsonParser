#!/usr/bin/python
'''Thanks to totalhash for this script that has been edited by myself alittle to removes some errors.
Just need to make the L at the end of the hex values disappear'''
from __future__ import division

import sys
import pefile
import bitstring
import string
import bz2
import hashlib

#if len(sys.argv) < 2:
      #  print "no file specified"
       # sys.exit(0)
#exe = pefile.PE(sys.argv[1])

def get_peHash(filename):
	exe = pefile.PE(filename)
	#image characteristics
	img_chars = bitstring.BitArray(hex(exe.FILE_HEADER.Characteristics))
	#pad to 16 bits
	img_chars = bitstring.BitArray(bytes=img_chars.tobytes())
	img_chars_xor = img_chars[0:8] ^ img_chars[8:16]

	#start to build pehash
	pehash_bin = bitstring.BitArray(img_chars_xor)

	#subsystem - 
	sub_chars = bitstring.BitArray(hex(exe.FILE_HEADER.Machine))
	#pad to 16 bits
	sub_chars = bitstring.BitArray(bytes=sub_chars.tobytes())
	sub_chars_xor = sub_chars[0:8] ^ sub_chars[8:16]
	pehash_bin.append(sub_chars_xor)

	#Stack Commit Size
	stk_size = bitstring.BitArray(hex(exe.OPTIONAL_HEADER.SizeOfStackCommit))
	stk_size_bits = string.zfill(stk_size.bin, 32)
	#now xor the bits
	stk_size = bitstring.BitArray(bin=stk_size_bits)
	stk_size_xor = stk_size[8:16] ^ stk_size[16:24] ^ stk_size[24:32]
	#pad to 8 bits
	stk_size_xor = bitstring.BitArray(bytes=stk_size_xor.tobytes())
	pehash_bin.append(stk_size_xor)

	#Heap Commit Size
	hp_size = bitstring.BitArray(hex(exe.OPTIONAL_HEADER.SizeOfHeapCommit))
	hp_size_bits = string.zfill(hp_size.bin, 32)
	#now xor the bits
	hp_size = bitstring.BitArray(bin=hp_size_bits)
	hp_size_xor = hp_size[8:16] ^ hp_size[16:24] ^ hp_size[24:32]
	#pad to 8 bits
	hp_size_xor = bitstring.BitArray(bytes=hp_size_xor.tobytes())
	pehash_bin.append(hp_size_xor)

	#Section chars
	for section in exe.sections:
		#virutal address
		sect_va =  bitstring.BitArray(hex(section.VirtualAddress))
		sect_va = bitstring.BitArray(bytes=sect_va.tobytes())
		sect_va_bits = sect_va[8:32]
		pehash_bin.append(sect_va_bits)
	 
		#rawsize
		sect_rs =  bitstring.BitArray(hex(section.SizeOfRawData))
		sect_rs = bitstring.BitArray(bytes=sect_rs.tobytes())
		sect_rs_bits = string.zfill(sect_rs.bin, 32)
		sect_rs = bitstring.BitArray(bin=sect_rs_bits)
		sect_rs = bitstring.BitArray(bytes=sect_rs.tobytes())
		sect_rs_bits = sect_rs[8:32]
		pehash_bin.append(sect_rs_bits)
	 
		#section chars
		hex_characterisitics = str(hex(section.Characteristics))
		if hex_characterisitics.endswith("L"):
			hex_characterisitics= hex_characterisitics[:-1]
		#print hex_characterisitics
		#sect_chars =  bitstring.BitArray(hex(section.Characteristics))
		sect_chars =  bitstring.BitArray(hex_characterisitics)
		sect_chars = bitstring.BitArray(bytes=sect_chars.tobytes())
		sect_chars_xor = sect_chars[16:24] ^ sect_chars[24:32]
		pehash_bin.append(sect_chars_xor)
	 
		#entropy calulation
		address = section.VirtualAddress
		size = section.SizeOfRawData
		raw = exe.write()[address+size:]
		if size == 0:
			kolmog = bitstring.BitArray(float=1, length=32)
			pehash_bin.append(kolmog[0:8])
			continue
		bz2_raw = bz2.compress(raw)
		bz2_size = len(bz2_raw)
		#k = round(bz2_size / size, 5)
		k = bz2_size / size
		kolmog = bitstring.BitArray(float=k, length=32)
		pehash_bin.append(kolmog[0:8])

	m = hashlib.sha1()
	m.update(pehash_bin.tobytes())
	return m.hexdigest()

#except:
   # print "ERROR not PE"
