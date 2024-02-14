import socket
import threading, json
import sys, time
from dataclasses import *
import pickle
import hashlib

@dataclass
class AuthToken:
    name: str
    passwd: str
    token: str
    

class GossipAuth:
    def __init__(self, host, port):
        # Node info
        self.host = host
        self.port = port
        self.node_type = "AUTH_NODE"
        self.master = ("100.79.33.125", 50000)
        self.load = 0

        # Logins
        self.clientlist = [ 
            AuthToken(
                name = "User",
                passwd = "Password",
                token = "cats"
            ) ]

        # Listener
        self.AuthNode_Socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.AuthNode_Socket.bind((self.host, self.port))
        self.AuthNode_Socket.listen(5)

    def connect_to_master(self):
        MasterNode_Sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        MasterNode_Sock.connect(self.master)
        MasterNode_Sock.sendall((f"{self.node_type}/{self.host}:{self.port}").encode("utf-8"))
        while True:
            try:
                data = MasterNode_Sock.recv(1024)
                
                if not data:
                    MasterNode_Sock.close() 
                    print("Closing socket")
                    break
                message = data.decode("utf-8")
                if message == "checkload":
                    MasterNode_Sock.sendall(f"checkload/{str(self.load)}".encode("utf-8"))
                    
            except socket.error as e:
                print(f"socket error: {e}")
            

            
    def start(self):
        master_thread = threading.Thread(target=self.connect_to_master)
        master_thread.start()
        
        while True:
            new_client, addr = self.AuthNode_Socket.accept()
            print(f"Auth Node {self.host, self.port} has new client: {addr}")
            client_thread = threading.Thread(target=self.handle_client, args=(new_client,addr,))
            client_thread.start()
            

    def handle_client(self, client_socket, addr):
        try:
            self.load+=1
            while True:
                data = client_socket.recv(1024).decode("utf-8")
                
                if not data:
                    break  # Exit the loop if data is empty (client closed the connection)
                if data == "login":
                    is_authed = False
                    login = client_socket.recv(1024).decode("utf-8")
                    username, passwd = login.split("/")
                    for c in self.clientlist:
                        if c.name == username and c.passwd == passwd:
                        # Verify the Username and password given as stored within the above list.
                        # "cats" could be replaced with a method to generate a random hash associated with
                        # the password, for example.
                            token = c.token
                            
                            client_socket.sendall(token.encode("utf-8"))
                            is_authed = True
                        
                    if not is_authed:
                        client_socket.sendall("Failed".encode("utf-8"))
                elif data == "signup":
                    login = client_socket.recv(1024).decode("utf-8")
                    username, passwd = login.split("/")
                    token = self.generate_md5(passwd)
                    
                    new_user = AuthToken(name=username, passwd=passwd, token=token)
                    self.clientlist.append(new_user)
                    if AuthToken(name=username, passwd=passwd, token=token) in self.clientlist:
                        client_socket.sendall("Account created. Please login.".encode("utf-8"))
                    else:
                        client_socket.sendall("Account creation failed.".encode("utf-8"))

                elif data == "verify":
                    token = client_socket.recv(1024).decode("utf-8")
                    verified = False
                    
                    for c in self.clientlist:
                        if c.token == token:
                            client_socket.sendall("Success".encode("utf-8"))
                            verified = True
                            break
                    
                    if verified is not True:
                        client_socket.sendall("Failed".encode("utf-8"))



        except ConnectionResetError:
            pass
        finally:
            
            self.load-=1
            client_socket.close()
            print(f"{addr} has disconnected")

    def generate_md5(self, passwd):
        
        md5_hash = hashlib.md5()
        md5_hash.update(passwd.encode('utf-8'))
        hashed_passwd = md5_hash.hexdigest()
        return hashed_passwd

def test_ports(ip_address, port):

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((ip_address, port))
            s.close
            return True
            
    except socket.error:
        return False           
        
        
if __name__ == "__main__":
    selfhost = socket.gethostname()
    selfip = socket.gethostbyname(selfhost)
    selfport = 0
    for port in range(50001, 50005+1):
        if test_ports(selfip, port):
            selfport = port
            break
            
    server = GossipAuth(selfip, selfport)
    server.start()