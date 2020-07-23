import socket


#SERVER
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.bind(("102.41.18.1",12356))

s.listen(5)

while True:
    print("Waiting for connection")
    C_Socket,Addr = s.accept()
    print("Acccpet  : ",Addr)
    C_Socket.send(b'Hello')


#CLIENT
