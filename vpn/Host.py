#!/usr/bin/env python
###############################################################################
# Host.py
#
# This is the generic base class containing APIs for all shared code
###############################################################################

import socket
import Cryptography

def DEBUG(msg):
    """
    Just a wrapper around print. Allows us to neatly add additional debug
    information, or just simply silence all debug messages later
    """
    print(msg)

class Host(object):
    
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
    
    def sendEncrypted(self, key, msg):
        """
        Sends a message encrypted with the key. Returns the number of bytes sent
        """
        iv = Cryptography.generateRandomIV()
        encrypted = Cryptography.symmetricKeyEncrypt(key, iv, msg)
        hmac = Cryptography.hmac(key, iv, msg)
        # Full message format: IV | Message | HMAC
        self.TRACE("IV: {}\nEncrypted: {}\nHMAC: {}\n".format(iv, encrypted, hmac))
        fullMessage = iv + encrypted + hmac
        return self.send(fullMessage)
    
    def recvEncrypted(self, key):
        """
        Receives a message and decrypts it with the key. Returns the message as a string
        """
        msg = self.recv(1024)
        if len(msg) < Cryptography.SYMMETRIC_KEY_IV_SIZE + Cryptography.HMAC_LENGTH:
            DEBUG("Error: Message length too short")
            return None
        
        iv = msg[:Cryptography.SYMMETRIC_KEY_IV_SIZE]
        encrypted = msg[Cryptography.SYMMETRIC_KEY_IV_SIZE : len(msg) - Cryptography.HMAC_LENGTH]
        hmac = msg[-Cryptography.HMAC_LENGTH:]

        decrypted = Cryptography.symmetricKeyDecrypt(key, iv, encrypted)
        self.TRACE("IV: {}\nEncrypted: {}\nHMAC: {}\nDecrypted: {}\n".format(iv, encrypted, hmac, decrypted))
        verificationHMAC = Cryptography.hmac(key, iv, decrypted)
        if (verificationHMAC != hmac):
            DEBUG("Error: HMAC was incorrect")
            return None
        
        return decrypted
    
    def TRACE(self, msg):
        """
        Prints diagnostic messages for debugging the VPN connection.
        At the moment this is just a wrapper for a print statement.
        Later on this can be message publishing on a dedicated channel.
        """
        print(msg)
    
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
