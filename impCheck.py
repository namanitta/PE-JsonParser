import os
fp = "/home/cuckoo/Desktop/scripts/PE-Attributes/PE_Jsonparser/results/maldb/txt_files/"
for r, d, f in os.walk(fp):
	for files in f:
		mal = fp+files
		fi = open (mal)
		lines = fi.readlines()
		for line in lines:
			if "Imphash" in line:
				en = line.rfind(":")
				v = line[en+1:].strip().rstrip()
				if v == "None":
					pass
				else:
					print v
