import socket
import threading
from time import *
import pickle
import hashlib
import sys
import os

class GossipClient:
    def __init__(self):
        # Connection info
        self.MainNode_Socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.MainNode_Address = ("100.79.33.125", 50000)
        self.MainNode_Socket.connect(self.MainNode_Address)

        # Sub-node info
        self.HasAuth = False
        self.AuthNode_Socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.HasContent = False
        self.ContNode_Socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Program info
        self.localdir = os.path.dirname(os.path.realpath(__file__))

        # Client info
        self.NodeType = "Client"
        self.addr, self.port = self.MainNode_Socket.getsockname()
        self.auth_token = ""
        self.is_authed = False
        

    


    def start(self):
        self.MainNode_Socket.sendall(f"{self.NodeType}/{(self.addr, self.port)}".encode("utf-8"))
        while True:
            message = input("Enter message (or 'exit' to quit): ")
            if message.lower() == 'exit':
                self.MainNode_Socket.send(message.encode('utf-8'))
                self.MainNode_Socket.close()
                self.AuthNode_Socket.close()
                self.ContNode_Socket.close()
                break
            
            if message.lower == "testload auth":
                self.MainNode_Socket.sendall(message.encode("utf-8"))
            if message.lower == "testload cont":
                self.MainNode_Socket.sendall(message.encode("utf-8"))


            elif message.lower() == 'login':
                if not self.HasAuth:
                    self.create_socket("auth")
                    
                # Take login details, send intent and then inform user of result.

                username = input("Type your username: (User)")
                password = input("Type your password: (Password)")
                self.AuthNode_Socket.sendall("login".encode("utf-8"))
                self.AuthNode_Socket.sendall(f"{username}/{password}".encode("utf-8"))
                answer = self.AuthNode_Socket.recv(1024).decode("utf-8")
                if answer == "Failed":
                        print("Failed to authenticate. Try again.")

                else:
                    print(f"{answer} is your Auth token")
                    self.auth_token = answer
                    self.is_authed = True
                    
            

            elif message.lower() == 'signup':
                if not self.HasAuth:
                    self.create_socket("auth")
                    

                new_username = input("Type your selected username:")
                new_password = input("Now type your password:")
                # Tell node intent and then user details
                self.AuthNode_Socket.sendall("signup".encode("utf-8"))
                self.AuthNode_Socket.sendall(f"{new_username}/{new_password}".encode("utf-8"))
                answer = self.AuthNode_Socket.recv(1024).decode("utf-8")
                # Inform user of result
                print(answer)
                


            elif message.lower() == 'list':
                if self.is_authed:
                    if self.HasContent == False:
                        self.create_socket("cont")
                    
                    
                    self.ContNode_Socket.sendall("list".encode("utf-8"))
                    startlist= self.ContNode_Socket.recv(1024).decode("utf-8")
                    print(startlist)
                    while True:
                        contlist = self.ContNode_Socket.recv(1024).decode("utf-8")

                        if "finished" in contlist.lower():
                            print(contlist)
                            break  

                        else:
                            print(contlist)
                else:
                    print("Please login first.")



            elif 'download' in message.lower():
                if self.is_authed:
                    if self.HasContent == False:
                        self.create_socket("cont")
                
                self.ContNode_Socket.sendall(message.encode("utf-8"))
                command, content = message.split(maxsplit=1)
                conthash = self.ContNode_Socket.recv(1024).decode("utf-8")
                self.recevive_file(self.ContNode_Socket, content, conthash)


            elif (message.lower() == 'list' or message.lower() == 'download') and not self.is_authed:
                print("You are not authenticated. Log in first.")


            elif message.lower() == "authy":
                self.MainNode_Socket.send(message.encode("utf-8"))

            else:
                self.MainNode_Socket.send(message.encode('utf-8'))
        
    def recevive_file(self, connection, filename, exphash):
        filepath = filename
        if not filepath.endswith(".mp3"):
            filepath += ".mp3"
        filepath = f"{self.localdir}/{filename}"

        with open(filepath, 'wb') as file:
            while True:
                data = connection.recv(1024)
                try:
                    if data.decode("utf-8") == "finished":
                        break
                except:
                    pass
                file.write(data)

        # Calculate MD5 checksum after the file has been received
        checkhash = self.generate_md5(filepath)
        print("Expected hash:", exphash)
        print("Calculated hash:", checkhash)

        if checkhash != exphash:
            print("The file is corrupted")
        else:
            print(f"Successfully downloaded {filename}")
                
    def generate_md5(self, filepath):
        md5_hash = hashlib.md5()

        with open(filepath, 'rb') as file:
            # Read the file in chunks to handle large files
            for chunk in iter(lambda: file.read(1024), b''):
                md5_hash.update(chunk)

        return md5_hash.hexdigest()



    def create_socket(self, node_type):
        print(f"Trying to connect to {node_type}")
        if node_type == "auth":
            AuthNode_Address = self.get_AuthNode_Addr()
            self.AuthNode_Socket.connect(AuthNode_Address)
            self.HasAuth = True
        elif node_type == "cont":
            addr = self.get_ContNode_Addr()
            self.ContNode_Address = addr
            self.ContNode_Socket.connect(self.ContNode_Address)
            self.ContNode_Socket.sendall(self.auth_token.encode("utf-8"))
            conf = self.ContNode_Socket.recv(1024).decode("utf-8")
            
            if conf == "Success":
                print("Successful connection")
                self.HasContent = True
            else:
                print(conf)


    def get_AuthNode_Addr(self):
        make_req = "auth_req"
        self.MainNode_Socket.send(make_req.encode("utf-8"))
        answer = self.MainNode_Socket.recv(1024)
        
        answer = pickle.loads(answer)
        host, port = answer.split(":")
        ip = socket.gethostbyname(host)
        port = int(port)  # Convert port to integer
        
        return ip, port

    def get_ContNode_Addr(self):
        make_req = "cont_req"
        self.MainNode_Socket.send(make_req.encode("utf-8"))
        answer = self.MainNode_Socket.recv(1024)

        answer = pickle.loads(answer)
        host, port = answer.split(":")
        ip = socket.gethostbyname(host)
        port = int(port)  # Convert port to integer
        
        return ip, port


    def receive_broadcasts(self):
        broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        broadcast_socket.bind(('0.0.0.0', 0))  # Bind to any available port
        broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        while True:
            data, _ = broadcast_socket.recvfrom(1024)
            message = data.decode('utf-8')
            print(f"Received broadcast: {message}")

if __name__ == "__main__":
    client = GossipClient()
    client.start()
