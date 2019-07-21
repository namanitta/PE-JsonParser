import pefilev2
import importlib
import sys
import array
import math
import hashlib
import pydeep
import peHash
import json
import os

def get_hash(filename):
	fh = open(filename, 'rb')
	m = hashlib.md5()
	s = hashlib.sha1()
	s256 = hashlib.sha256()
	
	while True:
		data = fh.read(8192)
		if not data:
			break

		m.update(data)
		s.update(data)
		s256.update(data)

	md5  = m.hexdigest()
	sha1 = s.hexdigest()
	sha256 = s256.hexdigest()
	my_fuzzy = pydeep.hash_file(filename)
	
	try:
		pehash = peHash.get_peHash(filename)
	
	except:
		 pehash = None

	hashes ={"MD5":md5,"SHA1":sha1,"SHA256":sha256,"Fuzzy Hash": my_fuzzy,"peHash":pehash}
	return hashes

def entropy_H(data):
        """Calculate the entropy of a chunk of data."""

        if len(data) == 0:
            return 0.0

        occurences = array.array('L', [0]*256)

        for x in data:
            occurences[ord(x)] += 1

        entropy = 0
        for x in occurences:
            if x:
                p_x = float(x) / len(data)
                entropy -= p_x*math.log(p_x, 2)

        return entropy
        
def analyse(filename):
	f = open(filename, 'rb')
	filedata = f.read()
	f.close()
	pe = pefilev2.PE(data=filedata, fast_load=True)
	pe.parse_data_directories()
	ent = entropy_H(filedata)
	hashes  = get_hash(filename)
	ih = pe.get_imphash()
	hashes.update({"File Entropy":ent})
	hashes.update({"Imphash":ih})

	slashed = filename.split('/')
	namefile = slashed[len(slashed)-1]
	hashes.update({"Filename" :namefile})
	
	return hashes,pe
	
def convertJson(fname):
	f = open(fname)
	lines = f.readlines()
	headers = []
	ind = []
	header_indices = {}
	pe_dict = {}
	m = [ ".DLL", ".dll"]
	for num, line in enumerate(lines):
		if line.strip():
			line = line.lstrip(' ')
			if line[0] ==  "|":
				ind.append(num)
				header = line[1:].rstrip()
				if header not in headers:
					headers.append(header)
					header_indices.update({header:[num]})
				else:
					header_indices[header].append(num)
	
	sub = {}
	sub_dict = {}
	sec = {}
	di = {}
	api = {}
	cont = False
	sec_ind = header_indices[[s for s in headers if "SECTION" in s][0]]
	if sec_ind[-1] == ind[-1]:
		sec_ind.append(sec_ind[-1]+21)
	else:
		sec_ind.append(ind[ind.index(sec_ind[-1])+1])
		#print sec_ind
		
	for n, line in enumerate(lines):
		if line.strip():
			line = line.lstrip(' ').rstrip()
			en = line.find(":")
			if n not in ind:
				if "LANG" in line:
					k = "LANG"
					v = line[line.rfind("][")+1:]
					
				elif ":" in line:
					k = line[0:en].strip(" ").rstrip()
					v = line[en+2:].strip().rstrip()
					if k == "DLL":
						pass
						
					if v.strip():
						if k == "id":
							cont = True
							t = "id"
							res = v
							pass
					else: 
						v = ""
					sub.update({k:v})
					
				elif n > sec_ind[-1]:
					if ".dll." in line:
						en = line.rfind(".")
						k = line[0:en].strip(" ").rstrip()
						v = line[en+1:].strip().rstrip()
						#Wanted to print api attached to Dll but not sure if it helps
						'''if k in api:
							api[k].append(v)
						else:
							api.update({k:[v]})
						sub.update(api)'''
						#print api
						# Listing all the APIS
						if "APIs" in sub_dict:
							if v not in sub_dict["APIs"]:
								sub_dict["APIs"].append(v)
							else:
								pass
						else: 
							sub_dict.update({"APIs":[v]})
							
						# Listing all the DLLS						
						if "DLLs" in sub_dict:
							if k not in sub_dict["DLLs"]:
								sub_dict["DLLs"].append(k)
							else:
								pass
						else: 
							sub_dict.update({"DLLs":[k]})
					elif any (x in line for x in m):
						k = line.strip().rstrip()
						if "DLLs" in sub_dict:
							if k not in sub_dict["DLLs"]:
								sub_dict["DLLs"].append(k)
							else:
								pass
						else: 
							sub_dict.update({"DLLs":[k]})
						
			else:
				if n == ind[0]:
					title = "FILE_INFO"
					md5 = sub["MD5"]
					sub_dict.update({title: sub})	
					sub = {}
				elif n == ind[4]:
					title = "HEADERS"
					sub_dict.update({title:sub})
					sub = {}
					
				elif n in sec_ind[1:]:
					#print
					title = sub["Name"]
					sec.update({title:sub})
					if n ==sec_ind[-1]:
						sub_dict.update({ "SECTION_HEADERS":sec})
					sub = {}
				elif n > sec_ind[-1]:
					title = line[1:].strip().rstrip()
					if title == 'IMAGE_RESOURCE_DIRECTORY_ENTRY':
						if cont:
							sub.update({t:res})
					if len(header_indices[title]) >1:
						if title in sub_dict:
							sub_dict[title].update({header_indices[title].index(n):sub})
							sub = {}
						else:
							sub_dict.update({title:{header_indices[title].index(n):sub}})
							sub = {}
							di = {}
					
					else:
						sub_dict.update({title:sub})
						sub = {}
	
	json_string = json.dumps( { md5 : sub_dict})
	f.close
	return json_string

def ensure_dir(filename):
	d = os.path.dirname(filename)
	if not os.path.exists(d):
		os.makedirs(d)
	

def main():
	
	if len(sys.argv) >= 2:
		filename =sys.argv[1]
		slashed1 = filename.split('/')
		namefile = slashed1[len(slashed1)-1]
		slashed2 = namefile.split('.')
		
		txtfile =  '/'.join(['results','txt_files','.'.join([slashed2[0],"txt"])])	
		jsonfile =  '/'.join(['results','json_files','.'.join([slashed2[0],"json"])])
		ensure_dir(txtfile)
		ensure_dir(jsonfile)	
		
		if len(sys.argv) >= 3:
			mods = sys.argv[2:len(sys.argv)]
		else:
			hashes, pe = analyse(filename)
			f = open(txtfile, 'w')
			for i, k in sorted(hashes.items()):
				line = ' : '.join ([str(i),str(k)])+"\n"
				f.write(line)
			p = str(pe)
			f.write(p)
			f.close
			
			j = open(jsonfile, 'w')
			j.write(convertJson(txtfile))
			j.close
			os.system("cat " +jsonfile +" | python -m json.tool >" + jsonfile)

	else:
		print "Usage %s <filename>" % sys.argv[0]
	
    
if __name__ =='__main__':
  main()
