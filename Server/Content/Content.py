import socket
import threading
from dataclasses import *
import hashlib
from time import *
import os
import pickle

@dataclass
class FileEntry:
    filename: str
    location: str
    hash: str


class GossipContent:
    def __init__(self, host, port):
        # Node info
        self.host = host
        self.port = port
        self.node_type = "CONTENT_NODE"
        self.master = ("100.79.33.125", 50000)
        self.load = 0
        self.localdir = os.path.dirname(os.path.realpath(__file__))
        self.auth_token = "cats"
        self.client_threads = { }

        # Master info
        self.MasterNode_Sock = None
        self.master_thread = threading.Thread(target=self.connect_to_master)
        self.master_thread.start()
        

        # Content info
        
        self.content_list = []
        self.content_list = self.get_content()
        
         # Call a method to generate and set the hash for each entry in content_list
        self.generate_hashes()

        
        
        

        # Listener
        self.ContentNode_Socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ContentNode_Socket.bind((self.host, self.port))
        self.ContentNode_Socket.listen(5)

     
    def connect_to_master(self):
        self.MasterNode_Sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.MasterNode_Sock.connect(self.master)
        self.MasterNode_Sock.sendall((f"{self.node_type}/{self.host}:{self.port}").encode("utf-8"))
        auth_addr_pickle = self.MasterNode_Sock.recv(1024)
        addr = pickle.loads(auth_addr_pickle)
        host, port = addr.split(":")
        ip = socket.gethostbyname(host)
        port = int(port)  # Convert port to integer
        self.AuthNode_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.AuthNode_sock.connect((ip, port))
        
        
        while True:
            try:
                data = self.MasterNode_Sock.recv(1024)
                
                if not data:
                    self.MasterNode_Sock.close() 
                    print("Closing socket")
                    break
                message = data.decode("utf-8")
                if message == "checkload":
                    self.MasterNode_Sock.sendall(f"checkload/{str(self.load)}".encode("utf-8"))
                    
            except socket.error as e:
                print(f"socket error: {e}")

    def get_content(self):
        filelist = [f for f in os.listdir(self.localdir) if os.path.isfile(os.path.join(self.localdir, f))]
        fileEntries = []
        for f in filelist:
            if f.endswith(".mp3"):
                entry = FileEntry(filename=f, location=f"{self.localdir}/{f}", hash=0)
                fileEntries.append(entry)
        return fileEntries
                

    def start(self):
        while True:
            new_client, addr = self.ContentNode_Socket.accept()
            print(f"Content Node {self.host, self.port} has new client: {addr}")
            client_thread = threading.Thread(target=self.handle_client, args=(new_client, addr,))
            client_thread.start()

    
    def handle_client(self, client_socket, addr):
        is_verified = False

        try:
            
            # Login verification
            data = client_socket.recv(1024)
            
            token = data.decode("utf-8")
            
            if not data:
                return
            
            self.AuthNode_sock.sendall("verify".encode("utf-8"))
            self.AuthNode_sock.sendall(token.encode("utf-8"))

            result = self.AuthNode_sock.recv(1024).decode("utf-8")
            
            if result == "Success":
                self.load+=1
                is_verified = True
                client_socket.sendall("Success".encode("utf-8"))
            else:
                is_verified = False
                client_socket.sendall("Failed Auth".encode("utf-8"))
            


        except:
            client_socket.sendall("There was an issue logging in. Try again.".encode("utf-8"))
            
        

        if is_verified == True:
            try:
                while True:
                
                    command = client_socket.recv(1024).decode("utf-8")

                    if command.lower() == "list":
                        client_socket.sendall("Start of song list:".encode("utf-8"))
                        for song in self.content_list:
                            reply = f"  {song.filename}\n"
                            client_socket.sendall(reply.encode("utf-8"))
                        finished = "Finished. To get a song, type 'download (name)'"
                        client_socket.sendall(finished.encode("utf-8"))

                    elif command.lower().startswith("download"):
                        _, content = command.split(maxsplit=1)
                        for song in self.content_list:
                            if content == song.filename:
                                client_socket.sendall(song.hash.encode("utf-8"))
                                
                                with open(song.location, 'rb') as file:
                                    try:
                                        counter = 0
                                        data = file.read(1024)
                                        while data:
                                            
                                            counter+=1
                                            client_socket.sendall(data)
                                            data = file.read(1024)
                                        
                                        client_socket.sendall("finished".encode("utf-8"))  
                                    except Exception as e:
                                        print(f"Error sending. {e}")
            except ConnectionResetError:
                    pass  # Connection was reset by the client
            finally:
                    self.load-=1
                    client_socket.close()
                    print(f"{addr} has disconnected")

        else:
            client_socket.sendall("You are not authenticated. Log in first.".encode("utf-8"))
            client_socket.close()

            
    
  
    def generate_hashes(self):
        for entry in self.content_list:
            entry.hash = self.generate_md5(entry.location)


    def generate_md5(self, filepath):
        md5_hash = hashlib.md5()

        with open(filepath, 'rb') as file:
            # Read the file in chunks to handle large files
            for chunk in iter(lambda: file.read(1024), b''):
                md5_hash.update(chunk)
        
        return md5_hash.hexdigest()

    
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
            
    server = GossipContent(selfip, selfport)
    server.start()
    
