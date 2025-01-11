import struct
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from os import path
from struct import pack, unpack, calcsize


class fileAES():
    def __init__(self, keytext, out_filename):
        hash = SHA256.new() # 해시 객체 생성
        hash.update(keytext.encode('utf-8')) # 해시 적용
        key = hash.digest() # 해시값 반환
        self.key = key[:16]

        iv_text = 'initialvector123' # 첫번째 블록은 이전 암호화 블록이 없기 때문에 iv사용
        hash.update(iv_text.encode('utf-8'))
        iv = hash.digest()
        del iv_text
        self.iv = iv[:16] # 16바이트
        
        self.out_filename = out_filename
        print('secret key: ', self.key)
        print('iv: ', self.iv)

    # AES 암호화
    def encrypt_file(self, filename, blocksize=65536):
        aes = AES.new(self.key, AES.MODE_CBC, self.iv)
        filesize = path.getsize(filename)
        if self.out_filename == None:
            out_filename = filename[0:len(filename)-4]+'.aef' # filesize, data
        else:
            out_filename = self.out_filename

        with open(filename, 'rb') as origin:
            with open(out_filename, 'wb') as ret:
                ret.write(pack('<Q', filesize)) # filesize를 c의 구조체 형식으로 저장
                while True:
                    block = origin.read(blocksize) # 블록단위로 파일 읽기. # AES는 128비트(16바이트)의 고정된 블록 단위로 암호화 수행
                    if len(block) == 0:
                        break
                    elif len(block) % 16 != 0:  # 16의 배수가 아니라면 0으로 채운다.
                        block += b'0'*(16 - len(block) % 16)
                    ret.write(aes.encrypt(block))

    # 암호된 파일을 복호화하는 메서드
    def decrypt_file(self, filename, file_exp, blocksize = 1024):

        with open(filename, 'rb') as origin: # 암호화 파일
            filesize = unpack('<Q', origin.read(calcsize('<Q')))[0]
            aes = AES.new(self.key, AES.MODE_CBC, self.iv)

            with open(file_exp, 'wb') as ret: # 복호화 파일
                ret.write(aes.decrypt(origin.read(16)))
                while True:
                    block = origin.read(blocksize) # 1024 블록 단위로 복호화 진행. 16의 배수라면 ok
                    if len(block) == 0:
                        break
                    ret.write(aes.decrypt(block))
                    print(aes.decrypt(block))
                ret.truncate(filesize) # filesize 만큼 패딩을 지우기위해 자르는 함수
