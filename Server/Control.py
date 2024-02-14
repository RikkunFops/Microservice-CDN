import socket
import threading
import subprocess
from dataclasses import *
import hashlib
from time import *
import pickle
import os

class GossipControl:
    def __init__(self, host, port):
        # Node Info
        self.host = host
        self.port = port
        self.node_type = "CONTROL_NODE"
        self.prime = ("100.79.33.125", 50000)
        self.localdir = os.path.dirname(os.path.realpath(__file__))
        self.contdir = f"{self.localdir}/Content/Content.py"
        self.authdir = f"{self.localdir}/Auth/Auth.py"
        self.load = 0

    def connect_to_master(self):
        MasterNode_Sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        MasterNode_Sock.connect(self.prime)
        MasterNode_Sock.sendall((f"{self.node_type}/{self.host}:{self.port}").encode("utf-8"))
        while True:
            data = MasterNode_Sock.recv(1024)
            if not data:
                break
            message = data.decode("utf-8")
            if message == "SPAWN_CONT":
                print("Spawning Content Node.")
                subprocess.Popen(['py', self.contdir], shell=True)
                pass
            if message == "SPAWN_AUTH":
                print("Spawning Auth Node")
                subprocess.Popen(['py', self.authdir], shell=True )
                pass

    def get_prime_addr(self):
        while True:
            prime_addr = input("Enter the address of the prime node:")
            try:
                prime_addr, prime_port=prime_addr.split(":")
                prime_port  = int(prime_port)
                break
            except:
                print("Please type the address in the format '0.0.0.0:12345")

        
        return (prime_addr, prime_port)

    def start(self):
        master_thread = threading.Thread(target=self.connect_to_master)
        master_thread.start()




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
            
    server = GossipControl(selfip, selfport)
    server.start()
    
