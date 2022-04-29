from pkgutil import get_data
import vt
import requests

programRunning = True

while programRunning == True:
    print("Enter your API key:", end = ' ')
    apikey = "8b9b9e4e5ef59d47c5e31182ba4c70ca1a6441ad1e6b2a1872367c8eb5f3a513"
    apikey.strip()
  #  if len(apikey) != 64:
   #   print("You did not enter a full 64 character API key!")
   #   continue
    client = vt.Client(apikey)
    print("Enter your hash:", end = ' ')
    hash = "9001567e2025f83c936b8746fd3b01e44572f70d8ddec39b75b9459f7e5089c8"
    hash.strip()
    hash.lower()
    if len(hash) == 64:
        x = re.findall(r"^[a-f0-9]{64}(:.+)?$", hash)
        if x:
            print("Processing hash")
        else:
            print("invalid hash")
            continue
    elif len(hash) == 32:
        x = re.findall(r"^[a-f0-9]{32}(:.+)?$", hash)
        if x:
            print("Processing hash")
        else:
            print("Invalid hash")
            continue

    file = client.get_object("/files/" + hash)
    

    detection_count = file.last_analysis_stats['malicious']
    if detection_count > 5:
        print("Detected by more than 5 AV engines!")
        print("Detected by " + str(detection_count) + " different anti virus engines.")
    elif detection_count < 5:
        print("Detected by less than 5 AV engines!")
        print("This file may be malicious.")
        print("Detected by " + str(detection_count) + " different anti virus engines.")
    elif detection_count == 0:
        print("No detections!")
        print("File is clean!")
    
    api_url = "https://www.virustotal.com/api/v3/files/" + hash
    HTTP_Response = str(requests.get(api_url, headers = {"X-Apikey":apikey}))
    HTTP_Response = HTTP_Response.split('[')
    HTTP_Response = HTTP_Response[1]
    HTTP_Response = HTTP_Response.replace("]>", "")
    if HTTP_Response != '200':
        print("Your HTTP response code was not 200")
        print("Your HTTP response was " + HTTP_Response)
    print("HTTP Status Code " + str(HTTP_Response))
    client.close()
    
    
    
    programRunning = False
