#!/usr/bin/env python
import Host
import Cryptography

class Server(Host.Host):
    
    def __init__(self, ipAddr = "127.0.0.1", portNum = 32694, sharedSecret="iloveildar"):
        super(Server, self).__init__(ipAddr, portNum, sharedSecret)
        
    def handshake(self):
        """
        Connect and start the handshake.
        Return true if connection and handshake are successful
        """
        self.initServer()
        
        # Receive RandomA
        recv1 = self.recv()
        sessionID = recv1[:Cryptography.SYMMETRIC_KEY_KEY_SIZE]
        RA = recv1[Cryptography.SYMMETRIC_KEY_KEY_SIZE:]
        self.TRACE("1 Recv:\nsessionId: {}\nRA: {}\n".format(sessionID, RA))
        
        # Send reply: RandomB, h(msg, "SRVR", sharedSecret)
        RB = Cryptography.generateSymmetricKey();
        msg = str(sessionID) + str(RA)
        hash1 = Cryptography.hash(msg + "SRVR" + str(self.sharedSecret))
        self.TRACE("2 Send:\nRB: {}\nhash1: {}\n".format(RB, hash1))
        send1 = RB + hash1
        self.send(send1)
        
        # Receive h(msgs, "CLNT", sharedSecret)
        recv2 = self.recv()
        self.TRACE("3 Recv:\nhash <{}>\n".format(recv2))
        hash2 = Cryptography.hash(recv1 + send1 + "CLNT" + str(self.sharedSecret))
        if recv2 != hash2:
            print("Error: Unexpected hash2")
            return False
        
        # TODO: Move this
        self.sessionKey = Cryptography.generateSymmetricKey()
        self.send(self.sessionKey)
        
        print("Handshake esablished")
        return True
    
    def run(self):
        """
        Main code
        """
        print("Running Server")
        
        handshakeSuccessful = self.handshake()
        if not handshakeSuccessful:
            print("Handshake failed.")
            return
        
        # Data is now protected
        while True:
            # Send and receive data
            
            # TODO: implement a chat, not an echo
            # msg = self.recv()
            msg = self.recvEncrypted(self.sessionKey)
            if not msg:
                self.close()
                print("Client disconnected. Done.")
                return
            
            print("Received ({}): {}".format(len(msg), msg))
            # Echo the message
            self.sendEncrypted(self.sessionKey, msg)

###############################################################################
# Test code
###############################################################################
if __name__ == "__main__":
    import argparse
    import sys
    parser = argparse.ArgumentParser(description="Test executable for Host module")

    parser.add_argument(
        'port',
        type=int,
        nargs="?",
        help="Port number",
        default=32694)

    args = parser.parse_args()
    
    port = args.port
    
    server = Server(portNum = port)
    server.run()