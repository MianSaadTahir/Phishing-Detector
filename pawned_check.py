import requests
import hashlib

HIBP_URL_PASSWORD = "https://api.pwnedpasswords.com/range/"

def check_password_pawned(password, return_hash=False):
    """Check if a password has been pawned using SHA1 hashing."""
    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    
    response = requests.get(f"{HIBP_URL_PASSWORD}{prefix}")
    if response.status_code == 200:
        hashes = response.text.splitlines()
        for hash_entry in hashes:
            hash_suffix, count = hash_entry.split(":")
            if hash_suffix == suffix:
                return (int(count), sha1_hash) if return_hash else int(count)
        return (0, sha1_hash) if return_hash else 0
    return "Error checking password"
