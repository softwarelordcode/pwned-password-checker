'''
This script checks if a password has been exposed in data breaches using the 
"Have I Been Pwned" API.
It uses the k-anonymity model to protect user privacy.
It sends a request to the API with the first 5 characters of the SHA-1 hash of the password.
'''
import hashlib
import requests

password = "12345"
hashed_pass = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
url = "https://api.pwnedpasswords.com/range/" + hashed_pass[:5]

response = requests.get(url,timeout=10)

if response.status_code == 200:
    print("Password has been pwned!")
    for line in response.text.splitlines():
        hash_part = line.split(":")[0]
        count = line.split(":")[1]
        print(f"Hash: {hash_part}, Count: {count}")
else:
    print("Password is \"safe\".")
    print(response.text)
