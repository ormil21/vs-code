import os
import socket
import ssl



def generate_new_key(client_ip):
    random_key= os.urandom(32) #32 bit for 256-bit key
    with open("C:/Users/ormil/Downloads/keys/{}".format(client_ip), "wb") as keyfile:
        keyfile.write(random_key)
    return random_key

def read_exiting_key(client_ip):
    with open("C:/Users/ormil/Downloads/keys/{}".format(client_ip), "rb") as keyfile:
        key= keyfile.read()
        return key





sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(("127.0.0.1", 8080))
sock.listen(1)

print("Server is listening")
while True:
    connection, address = sock.accept()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile="server.crt", keyfile="server.key")
    ssl_connection = ctx.wrap_socket(connection, server_side=True)
    ip,port =ssl_connection.getpeername()
    random_key=generate_new_key(ip)
    # random_key=read_exiting_key(ip)
    ssl_connection.sendall(random_key)



