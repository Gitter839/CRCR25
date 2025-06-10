## hashlib is another library that we can use, connect very well with hmac library
import hashlib
import hmac
import secrets
from Cryptodome.Random import get_random_bytes
if __name__ == '__main__':
    digest_generator = hashlib.sha256()
    digest_generator.update(b'First chunk of data')
    digest_generator.update(b'Second chunck of data')

    print(digest_generator.hexdigest())

    secret = get_random_bytes(32)
    mac_generator = hmac.new(secret,b'message to hash',hashlib.sha256)
    hmac_sender = mac_generator.hexdigest()
    print(mac_generator.hexdigest())


#------------------ At the verifier 

mac_gen_recivier = hmac.new(secret,b'message to _hash',hashlib.sha256) # type: ignore
hmac_ver = mac_gen_recivier.hexdigest()


if hmac.compare_digest(hmac_sender, hmac_ver ):
    print("OK")
else:
    print("HMAC different")