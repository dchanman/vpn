#!/usr/bin/env python
###############################################################################
# Host.py
#
# This is the generic base class containing APIs for all shared code
###############################################################################

import socket
import threading
import Cryptography
import binascii
import sys
from Client import Client
from Server import Server

def DEBUG(msg):
    """
    Just a wrapper around print. Allows us to neatly add additional debug
    information, or just simply silence all debug messages later
    """
    print(msg)

class Host(object):
    
    def __init__(self, ipAddr, portNum, sharedSecret, verbose = False):
        self.ipAddr = ipAddr
        self.portNum = portNum
        self.sharedSecret = sharedSecret
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connection = None
        self.cumulativeHmac = ""
        self.connectionClosed = False
        self.verbose = verbose
    
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
        Sends a message encrypted with the key. Returns the number of bytes sent.
        Also updates the cumulativeHmac
        """
        iv = Cryptography.generateRandomIV()
        encrypted = Cryptography.symmetricKeyEncrypt(key, iv, msg)
        hmac = Cryptography.hmac(key, iv, msg)
        
        self.cumulativeHmac = Cryptography.hash(self.cumulativeHmac + hmac)
        
        # Full message format: IV | Message | HMAC
        self.TRACE("IV: {}\nEncrypted: {}\nHMAC: {}\nCumulative HMAC: {}\n".format(binascii.hexlify(iv), binascii.hexlify(encrypted), hmac, self.cumulativeHmac))
        fullMessage = iv + encrypted + self.cumulativeHmac
        return self.send(fullMessage)
    
    def recvEncrypted(self, key):
        """
        Receives a message and decrypts it with the key. Returns the message as a string
        Also updates the cumulativeHmac
        """
        msg = self.recv(1024)
        if len(msg) < Cryptography.SYMMETRIC_KEY_IV_SIZE + Cryptography.HMAC_LENGTH:
            return None
        
        iv = msg[:Cryptography.SYMMETRIC_KEY_IV_SIZE]
        encrypted = msg[Cryptography.SYMMETRIC_KEY_IV_SIZE : len(msg) - Cryptography.HMAC_LENGTH]
        receivedCumulativeHmac = msg[-Cryptography.HMAC_LENGTH:]

        decrypted = Cryptography.symmetricKeyDecrypt(key, iv, encrypted)
        calculatedHMAC = Cryptography.hmac(key, iv, decrypted)
        self.cumulativeHmac = Cryptography.hash(self.cumulativeHmac + calculatedHMAC)
        
        self.TRACE("IV: {}\nEncrypted: {}\nDecrypted: {}\nComputed HMAC: {}\nReceived Cumulative HMAC: {}\nCalculated Cumulative HMAC: {}\n".format(binascii.hexlify(iv), binascii.hexlify(encrypted), decrypted, calculatedHMAC, receivedCumulativeHmac, self.cumulativeHmac))
        
        if (self.cumulativeHmac != receivedCumulativeHmac):
            DEBUG("Error: HMAC was incorrect")
            return None
        
        return decrypted
    
    ############################################################################
    # Code for the async chat
    ############################################################################
    class RecvEncryptedThread(threading.Thread):
        def __init__(self, host):
            threading.Thread.__init__(self)
            self.host = host
        
        def run(self):
            while not self.host.connectionClosed:
                msg = self.host.recvEncrypted(self.host.sessionKey)
                if not msg:
                    self.host.connectionClosed = True
                    print("Shutdown initiated... Press <ENTER> to terminate")
                    try:
                        self.host.send(None)
                    except:
                        pass
                    return
                print("Received ({}): {}".format(len(msg), msg))

    def startChat(self):
        recvThread = self.RecvEncryptedThread(self)
        recvThread.start()
        print("\nPlease type your message here.\nPress <ENTER> to send\nSend an empty message to terminate the session\nHave fun!\n")
        while not self.connectionClosed:
            # Send and receive data
            msg = raw_input()
            if self.connectionClosed:
                print("Connection detected to be closed...")
                break
            self.sendEncrypted(self.sessionKey, msg)
            if not msg:
                self.connectionClosed = True
                break
        
        print("Waiting for connection to finish... Press <ENTER> on the other connection")        
        recvThread.join()
        self.close()
        print("Receiver thread closed. Session ended.")        
                
    
    def TRACE(self, msg):
        """
        Prints diagnostic messages for debugging the VPN connection.
        At the moment this is just a wrapper for a print statement.
        Later on this can be message publishing on a dedicated channel.
        """
        if self.verbose:
            print(msg)
    
###############################################################################
# Test code
###############################################################################
def initSession(mode, ipAddr, port, sharedSecret, verbose):
    if mode == "client":
        makeClient(ipAddr, port, sharedSecret,verbose)
    elif mode == "server":
        makeServer(ipAddr, port, sharedSecret,verbose)


def makeClient(ipAddr, port, sharedSecret,verbose):
    client = Client(ipAddr, port, str(sharedSecret), " ", verbose)
    client.run()

def makeServer(ipAddr, port, sharedSecret,verbose):
    server = Server(ipAddr, port, str(sharedSecret), " ", verbose)
    server.run()


def selectMode():
    while True:
        try:
            userInput = raw_input("Input the mode you would like to operate as (client/server): ")
            validOptions = ['server','client']
        
            if userInput in validOptions:
                return userInput
            else:
                print("Error: invalid string")
        
        except ValueError:
            print("Error: invalid string")
            
def setPort():
    while True:
        try:
            userInput = int(raw_input("What port would you like to use? (10000+): "))
            if userInput >= 10000:
                print "You input: " + str(userInput)
                correct = checkInput()
                
                if correct == True:
                    return int(userInput)
            else:
                print("Error: invalid integer")
                    
        except ValueError:
            print("Error: invalid port")
    
def checkInput():
    while True:
        try:
            userInput = raw_input("Is this correct? (y/n): ")
            validOptions = ["y","n"]
            if userInput in validOptions:
                if userInput == "y":
                    return True
                else:
                    return False
            else:
                print("Error: invalid input")
        except ValueError:
            print("Error: invalid input")
    
def setSharedSecret():
    while True:
        try:
            userInput = raw_input("Input the new Shared Secret: ")
            print "You input: " + userInput
            
            correct = checkInput()
            
            if (correct == True):
                return userInput

        except ValueError:
            print("Error: invalid string")
            
def setIpAddr():
    while True:
        userInput = raw_input("Input the new IP Address: ")
        count = 0
        for char in userInput:
            if char == ".":
                count += 1;
    
        if count == 3:
            return userInput
        else:
            print("Error: Not a valid IP Address")
            
def toggleVerbose(verbose):
    return not verbose
    
def printMainOptions(mode, verbose, ipAddr, port, sharedSecret):
    #TODO: find a way to clear the prompt before doing all this
    print "Welcome to the main menu, here's a list of the current settings:"
    print "Mode:          " + mode
    print "IP Address:    " + ipAddr
    print "Port:          " + str(port)
    print "Shared Secret: " + str(sharedSecret)
    print "Verbose:       " + str(verbose)
    print("")
    
    print("What would you like to do?")
    print("0: Select the mode")
    print("1: Change the IP Address")
    print("2: Change the Port")
    print("3: Change the Shared Secret")
    print("4: Toggle Verbose")
    print("5: Initilize the VPN with the current settings")
    print("6: Exit")

def main():
    
    mode = "client"
    ipAddr = "127.0.0.1"
    port = 32694    
    sharedSecret = 42
    verbose = False


    while True:
        while True:
            try:
                printMainOptions(mode, verbose, ipAddr, port, sharedSecret)
                userInput = int(raw_input("Select function (0,1,2,3,4,5,6): "))
                validOptions = [0,1,2,3,4,5,6]
                
                if userInput in validOptions:
                    print("")
                    break
                else:
                    print("Error: invalid function selection.")
        
            except ValueError:
                print("Error: you must enter a valid integer.")
            
        if userInput == 0:
            mode = selectMode()
        elif userInput == 1:
            ipAddr = setIpAddr()
        elif userInput == 2:
            port = setPort()
        elif userInput == 3:
            sharedSecret = setSharedSecret()
        elif userInput == 4:
            verbose = toggleVerbose(verbose)
        elif userInput == 5:
            initSession(mode, ipAddr, port, sharedSecret, verbose)
        elif userInput == 6:
            sys.exit(1)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\nUser keyboard interrupt") #TODO zza investigate, should go back to main shell loop