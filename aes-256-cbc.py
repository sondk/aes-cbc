import json
import base64
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad, unpad


class AESCipher(object):
    def __init__(self, key):
        self.key = base64.b64decode(key)

    def encrypt(self, plaintext):
        raw = pad(plaintext, AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(raw)
        iv = base64.b64encode(cipher.iv).decode('utf-8')
        ct = base64.b64encode(ct_bytes).decode('utf-8')
        return json.dumps({'iv':iv, 'ciphertext':ct})

    def decrypt(self, json_input):
        b64 = json.loads(json_input)
        iv = base64.b64decode(b64['iv'])
        ct = base64.b64decode(b64['ciphertext'])
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        #decrypted = cipher.decrypt(ct)
        #print(cipher.decrypt(ct).hex())
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt

secret_key = "8GnaZiecCxhwozNmUAMNww=="
aes = AESCipher(secret_key)
#print(aes.encrypt(b'0123456789abcde'))
#ivs = [base64.b64encode(bytes.fromhex(i)).decode('utf-8') for i in ['00112233445566778899aabbccddee' + format(i, '02x') for i in range(0,255)]]
ivs = [base64.b64encode(bytes.fromhex(i)).decode('utf-8') for i in ['00112233445566778899aabbccdd' + format(i, '02x') + 'd4' for i in range(0,255)]]
ivs = [base64.b64encode(bytes.fromhex(i)).decode('utf-8') for i in ['00112233445566778899aabbcc' + format(i, '02x') + 'e2d5' for i in range(0,255)]]

for iv in ivs:
    try:
        aes.decrypt('{"iv": "'+ iv +'", "ciphertext": "dbMWSc7+zQZp6/9ZdhqnPQ=="}')
    except:
        continue
    print(base64.b64decode(iv).hex())
print(base64.b64decode("j6eS9zuKGSH42mH7YHaE1w==").hex())
#print(aes.decrypt('{"iv": "j6eS9zuKGSH42mH7YHaE1w==", "ciphertext": "dbMWSc7+zQZp6/9ZdhqnPQ=="}'))
#print(aes.decrypt('{"iv": "j6eS9auKGSH42mH7YHaE1w==", "ciphertext": "dbMWSc7+zQZp6/9ZdhqnPQ=="}'))
/s/I1heaM4SKHHaVbi/myviettel-android-release-7-0-production-release-apk
