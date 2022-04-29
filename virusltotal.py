import vt
import requests
import re

programRunning = True

while programRunning == True:
    print("Enter your API key:", end = ' ')
    apikey = input()
    apikey.strip()
    if len(apikey) != 64:
      print("You did not enter a full 64 character API key!")
      continue

    client = vt.Client(apikey)
    

    print("Enter your hash:", end = ' ')
    hash = input()
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
    try:
        file = client.get_object("/files/" + hash)
    except vt.error.APIError:
        print('API Error, Your API key, or hash file did not exist.')
        client.close()
        break
    

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
