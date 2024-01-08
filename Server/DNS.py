import socket
import threading
import subprocess
from time import *
import json
from dataclasses import *
import pickle
import os
import cmd
import sys


@dataclass
class Node:
    name: str
    addr : tuple
    type: str
    load: int
    socket : socket


class GossipServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.clientlist = []
        self.Auth_Nodes = []
        self.Content_Nodes = []
        self.Control_Nodes = []
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.authChild = 0
        self.contentChild = 0
        self.controlChild = 0
        self.clients = 0
        self.blockAuthUpdate = False
        self.blockContUpdate = False


    def checkloads(self, node_type):
        if node_type == "auth":
            if len(self.Auth_Nodes) == 0:
                print(f"No nodes of {node_type} exist. Spawning new node.")
                self.spawn_node(node_type)
                   
            for node in self.Auth_Nodes:
                if node.load < 5:
                    break
                else:
                    print("All auth nodes loaded. Spawning new node.")
                    self.spawn_node(node_type)
  
        elif node_type == "cont":
            if len(self.Content_Nodes) == 0:
                    print(f"No nodes of {node_type} exist. Spawning new node.")
                    self.spawn_node(node_type)
                    
            for node in self.Content_Nodes:
                if node.load < 5:
                    break
                else:
                    self.spawn_node(node_type)
                    print("All content nodes loaded. Spawning new node.")

            


    def least_loaded(self, node_type):
        load = 10000  # Initialize with positive infinity for comparison
        target = ("",0)

        if node_type == "auth":
            for node in self.Auth_Nodes:
                if node.load <= load and node.load < 5:
                    load = node.load
                    target = node.addr
                                    
        elif node_type == "cont":
            for node in self.Content_Nodes:
                if node.load <= load:
                    load = node.load
                    target = node.addr
        print(target)    
        return target

    def spawn_node(self, node_type):
        if not self.Control_Nodes:
            print("No control nodes available.")
            return

        control_node = self.Control_Nodes[0]
        print(f"Using control node: {control_node}")

        if node_type == "auth":
            spawn_message = "SPAWN_AUTH"
        elif node_type == "cont":
            spawn_message = "SPAWN_CONT"
        else:
            print("Invalid node_type")
            return

        control_node.socket.sendall(spawn_message.encode("utf-8"))
        self.Control_Nodes.pop(0)
        sleep(2)


    def pickle(self, data):
        serialised_data = pickle.dumps(data)
        return serialised_data

    def handle_client(self, client_socket):
        try:
            while True:
                data = client_socket.recv(1024)
                if not data:
                    break  # Exit the loop if data is empty (client closed the connection)
            
                message = data.decode('utf-8')
                print(f"Received message: {message}")
                if message.lower() == "exit" or "":
                    break

                elif message.lower() == "auth_req":
                    self.checkloads("auth")
                    auth_addr = self.least_loaded("auth")
                    sleep(2)
                    packed_data = self.pickle(auth_addr)
                    
                    client_socket.sendall(packed_data)
                    
                elif message.lower() == "cont_req":
                    self.checkloads("cont")
                    cont_addr = self.least_loaded("cont")
                    sleep(2)
                    packed_data = self.pickle(cont_addr)
                    
                    client_socket.sendall(packed_data)

                elif message.lower() == "testload auth":
                    if self.blockAuthUpdate == False:
                        self.blockAuthUpdate = True
                        for node in self.authNodes:
                            node.load = 5
                        self.checkloads("auth")
                        print("All auth nodes have been loaded.")
                    else:
                        self.blockAuthUpdate = False
                        print("Unlocked Auth node updates")

                elif message.lower() == "testload content":
                    if self.blockContUpdate == False:
                        self.blockContUpdate = True
                        for node in self.Content_Nodes:
                            node.load = 5
                        self.checkloads("cont")
                        print("All content nodes have been loaded.")
                    else:
                        self.blockAuthUpdate = False
                        print("Unlocked Auth node updates")

                elif message.lower() == "shutdown":
                    self.do_exit('')
                else:
                    print("Unknown command. Type 'help' for a list of commands.")

                
                # Broadcast the message to all connected clients
        except ConnectionResetError:
            pass  # Connection was reset by the client
        finally:
            print("Client disconnected")
            self.clientlist.remove(client_socket)
            client_socket.close()

    def handle_node(self, node_socket, node_type, addr):
        try:
            while True:
                # Send a request to the node to check its load
                node_socket.sendall("checkload".encode("utf-8"))

                # Receive the load information from the node
                load_data = node_socket.recv(1024).decode("utf-8")
                    
                if not load_data:
                # If no data is received, break out of the loop
                    break
                    
                    # Convert the received load information to an integer
                load = int(load_data)

                if node_type == "Auth" and not self.blockAuthUpdate:
                    for nodes in self.Auth_Nodes:
                        if nodes.addr == addr:
                            nodes.load = load
                            break
                elif node_type == "Content" and not self.blockContUpdate:
                    for nodes in self.Content_Nodes:
                        if nodes.addr == addr:
                            nodes.load = load
                            break

                # Sleep for a while before checking the load again
                sleep(5)
        except ConnectionResetError:
            pass  # Connection was reset by the client
        finally:
            print(f"{node_type} node disconnected")
            if node_type == "Auth":
                # Find the corresponding Auth node and remove it
                auth_node = next((node for node in self.authNodes if node.addr == addr), None)
                if auth_node:
                    self.authNodes.remove(auth_node)
                    self.authChild -=1
            elif node_type == "Content":
                # Find the corresponding Content node and remove it
                cont_node = next((node for node in self.Content_Nodes if node.addr == addr), None)
                if cont_node:
                    self.Content_Nodes.remove(cont_node)
                    self.contentChild -=1
            node_socket.close()

    def handle_control(self, client_socket, addr, name):
        print(f"New control node on {addr}")
        try: 
            data = client_socket.recv(1024).decode("utf-8")
        except ConnectionResetError:
            pass
        finally:
            self.controlChild -=1
            print(f"Control node {name} disconnected")




    def start(self):
        

        print(f"Server listening on {self.host}:{self.port}")


        while True:
            client_socket, addr = self.server_socket.accept()
            
            
            # Determine the type of connection based on connection
            connection_type, node_name, real_addr = self.determine_connection_type(client_socket)

            if connection_type == 'Auth':
                # Handle Auth node connection
                newAuth= Node(name=node_name, addr=real_addr, type="Auth", load=0, socket=client_socket)
                self.Auth_Nodes.append(newAuth)
                print(f"{newAuth.addr} is an Auth node")
                node_handler = threading.Thread(target=self.handle_node, args=(client_socket, "Auth", real_addr))
                node_handler.start()
            elif connection_type == 'Content':
                # Handle Content node connection
                newCont= Node(name=node_name, addr=real_addr, type="Cont", load=0, socket=client_socket)
                self.Content_Nodes.append(newCont)
                print(f"{newCont.addr} is a Content node")
                node_handler = threading.Thread(target=self.handle_node, args=(client_socket, "Content", real_addr))
                node_handler.start()
            elif connection_type == "Control":
                # Handle Control Node Connection
                newControl = Node(name=node_name, addr=real_addr, type="Control", load = 0, socket=client_socket)
                self.Control_Nodes.append(newControl)
                node_handler = threading.Thread(target=self.handle_control, args=(client_socket, real_addr, node_name))
                node_handler.start()                
            else:
                # Handle other connections (clients)
                self.clientlist.append(client_socket)
                print(f"New client on {real_addr}")
                client_handler = threading.Thread(target=self.handle_client, args=(client_socket,))
                client_handler.start()

    def determine_connection_type(self, client_socket):
    # Replace this logic with your criteria for determining connection type
    # For example, you might check the first message received from the client
        data = client_socket.recv(1024).decode('utf-8')
        if "AUTH_NODE" in data:
            node_type, addr = data.split("/")
            self.authChild +=1
            node_name = f"{node_type}{self.authChild}"

            return "Auth", node_name, addr
        
        elif "CONTENT_NODE" in data:
            node_type, addr = data.split("/")
            self.contentChild +=1
            node_name = f"{node_type}{self.contentChild}"

            return "Content", node_name, addr
        
        elif "CONTROL_NODE" in data:
            node_type, addr = data.split("/")
            node_name = f"{node_type}{self.controlChild}"
            self.controlChild +=1
            return "Control", node_name, addr    
    
        else:
            node_type, addr = data.split("/")
            self.clients+=1
        
            return 'Client', self.clients, addr
        
    def do_exit(self, arg):
        """Exit the server."""
        print("Exiting...")
        sys.exit()


if __name__ == "__main__":
    selfhost = socket.gethostname()
    selfip = socket.gethostbyname(selfhost)

    server = GossipServer(selfip, 50000)
    server.start()
    
