#!/usr/bin/env python
import Host
import Cryptography

class Server(Host.Host):
    
    def __init__(self, ipAddr = "127.0.0.1", portNum = 32694, sharedSecret="iloveildar", padding=" ", verbose = False):
        while len(sharedSecret) < Cryptography.SYMMETRIC_KEY_KEY_SIZE:
            sharedSecret += padding
        super(Server, self).__init__(ipAddr, portNum, sharedSecret)
        
    def handshake(self):
        """
        Connect and start the handshake.
        Return true if connection and handshake are successful
        """
        self.initServer()
        
        # Receive Encrypted Session Key and RandomA
        recv1 = self.recv()
        iv = recv1[:Cryptography.SYMMETRIC_KEY_IV_SIZE]
        encryptedSessionKey = recv1[Cryptography.SYMMETRIC_KEY_IV_SIZE:Cryptography.SYMMETRIC_KEY_IV_SIZE + Cryptography.SYMMETRIC_KEY_KEY_SIZE]
        RA = recv1[Cryptography.SYMMETRIC_KEY_IV_SIZE + Cryptography.SYMMETRIC_KEY_KEY_SIZE:]
        self.TRACE("1 Recv:\encryptedSessionKey: {}\nRA: {}\n".format(encryptedSessionKey, RA))
        
        # Send reply: RandomB, h(msg, "SRVR", sharedSecret)
        RB = Cryptography.generateNonce();
        hash1 = Cryptography.hash(recv1 + "SRVR" + str(self.sharedSecret))
        self.TRACE("2 Send:\nRB: {}\nhash1: {}\n".format(RB, hash1))
        self.TRACE("recv1: {}".format(recv1))
        
        send1 = RB + hash1
        self.send(send1)
        
        # Receive h(msgs, "CLNT", sharedSecret)
        recv2 = self.recv()
        self.TRACE("3 Recv:\nhash <{}>\n".format(recv2))
        hash2 = Cryptography.hash(recv1 + send1 + "CLNT" + str(self.sharedSecret))
        if recv2 != hash2:
            print("Error: Unexpected hash2")
            return False
        
        # Decrypt the session key using our shared secret
        self.sessionKey = Cryptography.symmetricKeyDecrypt(self.sharedSecret, iv, encryptedSessionKey)
        
        print("Handshake esablished")
        self.TRACE("Session Key: {}".format(self.sessionKey))
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
        self.startChat()

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
    parser.add_argument(
        'verbose',
        action="store_true",
        help="Display handshaking")

    args = parser.parse_args()
    
    server = Server(portNum = args.port, verbose = args.verbose)
    server.run()