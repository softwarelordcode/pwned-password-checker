'''
This script checks if a password has been exposed in data breaches using the 
"Have I Been Pwned" API.
It uses the k-anonymity model to protect user privacy.
It sends a request to the API with the first 5 characters of the SHA-1 hash of the password.
'''
import sys
import hashlib
import requests

def convert_to_sha1(passwd):
    """Convert a password to its SHA-1 hash."""
    return hashlib.sha1(passwd.encode('utf-8')).hexdigest().upper()

def request_api(query_chars):
    """Request the API with the hashed password."""
    url = "https://api.pwnedpasswords.com/range/" + query_chars
    res = requests.get(url, timeout=10)
    return res

def pwned_response_check(res, hashed_pass):
    """Check if the response from the API indicates a pwned password."""
    if res.status_code == 200:
        for line in res.text.splitlines():
            hash_part = line.split(":")[0]
            count = line.split(":")[1]
            if hashed_pass == hashed_pass[:5] + hash_part:
                return True, count
    return False, 0


def main(args):
    """"Main function to execute the password check."""

    try:
        password = args[1]
    except IndexError:
        print("Usage: python check_pass.py <pass>")
        sys.exit(1)

    hashed_pass = convert_to_sha1(password)
    response = request_api(hashed_pass[:5])
    is_pwned, count = pwned_response_check(response, hashed_pass)

    if is_pwned:
        print("Password has been pwned!")
        print(f"Your password has been found {count} times in data breaches.")
    else:
        print("Password is \"safe\".")

main(sys.argv)
