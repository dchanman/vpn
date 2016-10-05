#!/usr/bin/env python
###############################################################################
# Host.py
#
# This is the generic base class containing APIs for all shared code
###############################################################################

import socket

def DEBUG(msg):
    """
    Just a wrapper around print. Allows us to neatly add additional debug
    information, or just simply silence all debug messages later
    """
    print(msg)

class Host:
    
    def __init__(self, ipAddr, portNum, sharedSecret):
        self.ipAddr = ipAddr
        self.portNum = portNum
        self.sharedSecret = sharedSecret
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connection = None
    
    def initServer(self):
        """
        Initializes this host as a server.
        Will block until a connection with a client is established
        """
        DEBUG("Initializing server: {}:{}".format(self.ipAddr, self.portNum))
        self.socket.bind((self.ipAddr, self.portNum))
        self.socket.listen(1)
        self.connection, addr = self.socket.accept()
        self.socket.close()
        DEBUG("Connected to addr: {}".format(addr))
    
    def initClient(self):
        """
        Initializes this host as a client.
        """
        DEBUG("Initializing client: {}:{}".format(self.ipAddr, self.portNum))
        self.socket.connect((self.ipAddr, self.portNum))
        self.connection = self.socket
    
    def close(self):
        """
        Cleans up this host's socket
        """
        self.connection.close()

    def send(self, msg):
        """
        Sends a message. Returns the number of bytes sent
        """
        if self.connection is None:
            DEBUG("Error: Not connected")
            return 0
        return self.connection.send(msg)
    
    def recv(self, bufferSize = 1024):
        """
        Receives a message and returns it as a string
        """
        if self.connection is None:
            DEBUG("Error: Not connected")
            return ""
        return self.connection.recv(bufferSize)
        
###############################################################################
# Test code
###############################################################################
if __name__ == "__main__":
    import argparse
    import sys
    parser = argparse.ArgumentParser(description="Test executable for Host module")
    parser.add_argument(
        'mode',
        type=str,
        nargs=1,
        help="Either Client or Server mode",
        choices=["client", "server"])
    parser.add_argument(
        'port',
        type=int,
        nargs="?",
        help="Port number",
        default=32694)

    args = parser.parse_args()
    
    ipAddr = "127.0.0.1"
    port = args.port
    sharedSecret = 42
    
    if args.mode[0] == "client":
        client = Host(ipAddr, port, sharedSecret)
        try:
            client.initClient()
        except:
            print("Unable to connect. Is the server running?")
            sys.exit(1)
        
        while True:
            msg = raw_input("Please enter a message: ")
            client.send(msg)
            reply = client.recv()
            if len(reply) == 0:
                client.close()
                print("Server disconnected. Done.")
                sys.exit(0)
            print("Received ({}): {}".format(len(reply), reply))
                            
    elif args.mode[0] == "server":
        server = Host(ipAddr, port, sharedSecret)
        server.initServer()
        while True:
            msg = server.recv()
            if len(msg) == 0:
                server.close()
                print("Client disconnected. Done.")
                sys.exit(0)
            
            print("Received ({}): {}".format(len(msg), msg))
            # Echo the message
            server.send(msg)
        
    else:
        print("Invalid mode")
