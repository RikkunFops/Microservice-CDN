import socket
import threading, json
from dataclasses import *
import hashlib
from time import *
import os

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

        # Content info
        self.content_list = [
            FileEntry(
                filename= "sans",
                location=  f"{self.localdir}/sans.mp3",
                hash = 0
            )
        ]
         # Call a method to generate and set the hash for each entry in content_list
        self.generate_hashes()

        # Listener
        self.ContentNode_Socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ContentNode_Socket.bind((self.host, self.port))
        self.ContentNode_Socket.listen(5)

     
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
            new_client, addr = self.ContentNode_Socket.accept()
            print(f"Content Node {self.host, self.port} has new client: {addr}")
            client_thread = threading.Thread(target=self.handle_client, args=(new_client,))
            client_thread.start()


    def handle_client(self, client_socket):
        try:
            # Receive login information
            data = client_socket.recv(1024)
            if not data:
                return

            login = data.decode('utf-8')
            print(login)

            if login.lower() == self.auth_token:
                client_socket.sendall("Successfully Authenticated.".encode("utf-8"))

                # Receive and process one command
                data = client_socket.recv(1024)
                if not data:
                    return

                command = data.decode("utf-8")

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
                            print(song.hash)
                            with open(song.location, 'rb') as file:
                                try:
                                    data = file.read(1024)
                                    while data:
                                        client_socket.sendall(data)
                                        data = file.read(1024)
                                except Exception as e:
                                    print(f"Error sending. {e}")

            else:
                client_socket.sendall("You are not authenticated. Log in first.".encode("utf-8"))

        except ConnectionResetError:
            pass  # Connection was reset by the client
        finally:
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
    
