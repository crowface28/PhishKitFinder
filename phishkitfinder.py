import requests, re, io, zipfile, os

urls = []
f = open("threatUrls_out.csv")
for line in f:
	urls.append(line.strip())
f.close()

def direct(url):
	try:
		r = re.findall('[^\/]+', url) #splits url into all parts
		starter = r[0] + "//" + r[1] + "/" #url = http://<site>/
		for el in range(len(r)-3): 
			starter = starter + r[el+2] + ".zip" #starter = starter + next path level
			data = requests.get(starter, timeout=3)
			if data.status_code==200:
				if data.content[:2]=='PK':
					f = open(r[1]+"_direct.zip", 'wb') #r[1] = domain
					f.write(data.content)
					f.close()
					print "\tDirect zip found and downloaded!"
			starter = starter[:-4]+'/' #removes .zip, adds / for next path level
		return 1
	except Exception as e:
		print "Error in direct(): ", str(e)
		return 0

def regex(url):
	try:
		r = re.findall('[^\/]+', url) #splits url into all parts
		starter = r[0] + "//" + r[1] + '/' #url = http://<site>/
		for el in range(len(r)-3):
			starter = starter + r[el+2]+'/' #adds slash to each path level
			data = requests.get(starter, timeout=3)
			if ".zip" in data.text:  #if there's a .zip anywhere on the html..
				regZipX = re.findall("([^\s<>=\"]+\.zip)", data.text) #find all of them with a regex
				if len(regZipX) > 0: #if it found some, 
					try:
						regZip = set(regZipX) #dedup them
						for zipName in regZip: #for all the .zips...
							data = requests.get(starter+zipName,timeout=3) #try to get them at the path + the regexed zip name
							if data.status_code==200:
								if data.content[:2]=='PK':
									f = open(r[1]+"_regex_"+zipName, 'wb')
									f.write(data.content)
									f.close()
									print "\tRegex Zip found and downloaded!"
					except Exception as e:
						print "Error in regexer...", str(e)
	except Exception as e:
		print "Error in regexer..." + str(e)

def emailParse():
	emails=set()
	path = '/home/crow/phishkitfinder/'
	files = os.listdir(path)
	for file in files:
		if '.zip' in file:
			print "opening", file
			hit = re.search('(.*?)_', file)
			domain = hit.group(1)
			zipF = open(path+file)
			zipContent = zipF.read()
			zip = zipfile.ZipFile(io.BytesIO(zipContent), 'r')
			for fileName in zip.namelist():
				f = zip.open(fileName)
				contents = f.read()
				hit = re.findall("([\w_.+-]+\@[\w-]+\.\w+)", contents)
				if len(hit) > 0:
					for h in hit:
						emails.add((domain,h))
				f.close()
			os.rename('/home/crow/phishKitFinder/'+file, '/home/crow/phishKitFinder/processedKits/'+file)
	print "writing e-mails to file..."
	emailFile = open('emailsHarvested.txt', 'a')
	for email in emails:
		emailFile.write(email[0]+"\t"+email[1]+"\n")
	emailFile.close()

def expander(url):
	try:
		req = requests.get(url, allow_redirects=False, timeout=3)
		if req.status_code==302:
			url = req.headers['Location']
			return url
		else:
			return url
	except Exception as e:
		print "Error in expanderizer! ", str(e)
		return url
	
	
	
emails = set() #unique list of e-mail addresses

max = len(urls)
count = 0
		
for url in urls:
	count = count + 1
	print "on",count,"of",max,"(",url,")"
	if len(url) < 30:
		oldUrl = url
		url = expander(url)
		print "Original URL " + oldUrl + " expanded to " + url
	dir = direct(url) # try direct grabs
	reg = regex(url) # try parsing for .zip's

emailParse() # parse zips for e-mail addresses

