import requests, re, io, zipfile

urls = []
f = open("phishUrls.txt")
for line in f:
	urls.append(line.strip())
f.close()

emails = set()

max = len(urls)
count = 0
for url in urls:
	count = count + 1
	print "on",count,"of",max
	try:
		r = re.findall('[^\/]+', url)
		starter = r[0] + "//" + r[1] + "/"
		for el in range(len(r)-3):
			starter = starter + r[el+2] + ".zip"
			try:
				data = requests.get(starter, timeout=3)
				if data.status_code==200:
					if data.content[:2]=='PK':
						f = open(r[1]+"_direct.zip", 'wb')
						f.write(data.content)
						f.close()
						zip = zipfile.ZipFile(io.BytesIO(data.content), 'r')
						for fileName in zip.namelist():
							f = zip.open(fileName)
							contents = f.read()
							hit = re.findall("([\w_.+-]+\@[\w-]+\.\w+)", contents)
							if len(hit) > 0:
								for h in hit:
									emails.add(h)
							f.close()
			except Exception as e:
				print "error directly requesting .zip from " + starter + ": " + str(e)
			try:
				starter = starter[:-4] + "/"
				data = requests.get(starter, timeout=3)
				if ".zip" in data.text:
					#print "\t.zip detected in " + starter
					regZipX = re.findall("([^\s<>=\"]+\.zip)", data.text)
					if len(regZipX) > 0:
						try:
							regZip = set(regZipX)
							for zipName in regZip:
								data = requests.get(starter+zipName,timeout=3)
								if data.status_code==200:
									if data.content[:2]=='PK':
										f = open(r[1]+"_regex.zip", 'wb')
										f.write(data.content)
										f.close()
										zip = zipfile.ZipFile(io.BytesIO(data.content), 'r')
										for fileName in zip.namelist():
											f = zip.open(fileName)
											contents = f.read()
											hit = re.findall("([\w_.+-]+\@[\w-]+\.\w+)", contents)
											if len(hit) > 0:
												for h in hit:
													emails.add(h)
											f.close()
						except Exception as e:
							print "Error with zip regex: ", str(e)
			except Exception as e:
				print "Directory listing section problem: " + str(e)
	except Exception as e:
		print "Root error: " + str(e)
	
emailFile = open('emailsHarvested.txt', 'a')
for email in emails:
	print email
	emailFile.write(email+"\n")
emailFile.close()
	

