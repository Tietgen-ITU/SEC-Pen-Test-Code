from os import urandom
from binascii import hexlify
from backports.pbkdf2 import pbkdf2_hmac

def hash_password(password: str) -> tuple[str, str]:
    '''Hashes the given password using PBKDF2 with a random salt,
    and then returns the tuple (derived_key, salt).'''

    # The salt should be generated with a cryptographically secure
    # pseudorandom number generator (CSPRNG), such as os.urandom()
    salt = hexlify(urandom(32))

    # Hashes the password using the SHA256 hash function, across 100.000 generations
    derived_key = hexlify(pbkdf2_hmac('SHA256', password.encode('UTF-8'), salt, 100000))

    return derived_key, salt

def verify_password(password: str, derived_key: str, salt: str) -> bool:
    '''Verifies the given password against the given derived key and salt.
    Returns True if the password is correct, False otherwise.'''

    return derived_key == hexlify(pbkdf2_hmac('SHA256', password.encode('UTF-8'), salt, 100000))
