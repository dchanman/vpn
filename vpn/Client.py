#!/usr/bin/env python
import Host
import Cryptography

class Client(Host.Host):
    
    def __init__(self, ipAddr = "127.0.0.1", portNum = 32694, sharedSecret="iloveildar"):
        super(Client, self).__init__(ipAddr, portNum, sharedSecret)
        
    def handshake(self):
        """
        Connect and start the handshake.
        Return true if connection and handshake are successful
        """
        self.initClient()
        
        # Send RandomA
        sessionID = Cryptography.generateSymmetricKey()
        RA = Cryptography.generateSymmetricKey()
        self.TRACE("1 Send:\nsessionId: {}\nRA: {}\n".format(sessionID, RA))
        send1 = sessionID + RA
        self.send(send1)
                        
        # Wait for reply: RandomB, h(msg, "SRVR", sharedSecret)
        recv1 = self.recv(1024)
        RB = recv1[:Cryptography.SYMMETRIC_KEY_KEY_SIZE]
        hash1 = recv1[Cryptography.SYMMETRIC_KEY_KEY_SIZE:]
        self.TRACE("2 Recv:\nRB: {}\nhash1: {}\n".format(RB, hash1))
        msg = str(sessionID) + str(RA) + "SRVR" + str(self.sharedSecret) 
        if hash1 != Cryptography.hash(msg):
            self.TRACE("Error: Unexpected hash1")
            return False
            
        # Send h(msgs, "CLNT", sharedSecret)
        msg2 = send1 + recv1 + "CLNT" + str(self.sharedSecret)
        hash2 = Cryptography.hash(msg2)
        self.TRACE("3 Send:\nhash <{}>\n".format(hash2))
        self.send(hash2);
        
        # TODO: Move this
        self.sessionKey = self.recv()
        
        self.TRACE("Handshake esablished")
        return True
    
    def run(self):
        """
        Main code
        """
        print("Running Client")
        
        handshakeSuccessful = self.handshake()
        if not handshakeSuccessful:
            print("Handshake failed.")
            return
        
        # Data is now protected
        while True:
            # Send and receive data
            
            # TODO: implement a chat, not an echo
            msg = raw_input("Please enter a message: ")
            # client.send(msg)
            client.sendEncrypted(self.sessionKey, msg)
            reply = client.recvEncrypted(self.sessionKey)
            if len(reply) == 0:
                client.close()
                print("Server disconnected. Done.")
                sys.exit(0)
            print("Received ({}): {}".format(len(reply), reply))

###############################################################################
# Test code
###############################################################################
if __name__ == "__main__":
    import argparse
    import sys
    parser = argparse.ArgumentParser(description="Test executable for Client module")

    parser.add_argument(
        'port',
        type=int,
        nargs="?",
        help="Port number",
        default=32694)

    args = parser.parse_args()
    
    port = args.port
    
    client = Client(portNum = port)
    client.run()