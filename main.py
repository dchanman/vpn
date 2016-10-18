#!/usr/bin/env python
###############################################################################
# main.py
#
# This is the shell that interfaces with our vpn code
###############################################################################

import socket
import threading
import binascii
import sys
from Client import Client
from Server import Server


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
        sys.exit("\nUser keyboard interrupt")