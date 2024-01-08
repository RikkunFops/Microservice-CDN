import socket
import threading, json
import sys, time
from dataclasses import *
import pickle


@dataclass
class AuthToken:
    name: str
    passwd: str
    

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
                passwd = "Password"
                
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
            data = MasterNode_Sock.recv(1024)
            if not data:
                break
            message = data.decode("utf-8")
            if message == "checkload":
                MasterNode_Sock.sendall(str(self.load).encode("utf-8"))
            

            
    def start(self):
        master_thread = threading.Thread(target=self.connect_to_master)
        master_thread.start()
        
        while True:
            new_client, addr = self.AuthNode_Socket.accept()
            print(f"Auth Node {self.host, self.port} has new client: {addr}")
            client_thread = threading.Thread(target=self.handle_client, args=(new_client,))
            client_thread.start()

    def handle_client(self, client_socket):
        try:
            self.load+=1
            while True:
                data = client_socket.recv(1024).decode("utf-8")
                if not data:
                    break  # Exit the loop if data is empty (client closed the connection)
                username, passwd = data.split("/")
                if AuthToken(name=username, passwd=passwd) in self.clientlist:
                    # Verify the Username and password given as stored within the above list.
                    # "cats" could be replaced with a method to generate a random hash associated with
                    # the password, for example.
                    client_socket.sendall("cats".encode("utf-8"))
                else:
                    client_socket.sendall("Failed".encode("utf-8"))


        except ConnectionResetError:
            pass
        finally:
            
            self.load-=1
            client_socket.close()


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