#!/usr/bin/env python
import Host
import Cryptography
import binascii

class Server(Host.Host):
    
    def __init__(self, ipAddr = "127.0.0.1", portNum = 32694, sharedSecret="iloveildar", padding=" ", verbose = False):
        while len(sharedSecret) < Cryptography.SYMMETRIC_KEY_KEY_SIZE:
            sharedSecret += padding
        super(Server, self).__init__(ipAddr, portNum, sharedSecret, verbose = verbose)
        
    def handshake(self):
        """
        Connect and start the handshake.
        Return true if connection and handshake are successful
        """
        self.initServer()
        
        
        
        # Receive p, g, (g^a)modp and RandomA
        recv1 = self.recv(8000000).decode("utf-8")
        recv1Components = recv1.split(",")
        print(recv1)
        if len(recv1Components) != 4:
            print("Handshake error: Invalid number of message components: {}".format(len(recv1Components)))
            print("len: {}".format(len(recv1)))
            return False
            
        p = int(recv1Components[0])
        g = int(recv1Components[1])
        gamodp = int(recv1Components[2])
        RA = recv1Components[3]
        self.TRACE("1 Recv:\np: {}\ng: {}\ngamodp: {}\nRA: {}\n".format(
            p,
            g,
            gamodp,
            RA)
        )
        
        # Generate secret integer b
        b = Cryptography.generateRandomNumber()
        
        # Calculate (g^b)modp
        gbmodp = (g % p) ** b
        
        # Calculate session key
        gabmodp = gamodp ** b
        self.sessionKey = Cryptography.hash(str(gabmodp))[:Cryptography.SYMMETRIC_KEY_BLOCK_SIZE]
        self.TRACE("Session Key: {}\n".format(self.sessionKey))
        
        # Send reply: (g^b)modp, E(h(recv1, SRVR, self.sharedSecret), (g^ab)modp), IV
        IV2 = Cryptography.generateRandomIV()
        hash2 = Cryptography.hash(recv1 + "SRVR" + str(self.sharedSecret))
        self.TRACE("hash2: {}\n".format(hash2))
        ehash2 = Cryptography.symmetricKeyEncrypt(self.sessionKey, IV2, hash2)
        self.TRACE("ehash2: {}\n".format(ehash2))
        self.TRACE("2 Send:\n (g^b)modp: {}\n ehash2: {}\n IV2: {}".format(
            gbmodp,
            ehash2.encode("hex"),
            IV2.encode("hex"))
        )
        send2 = str(gbmodp) + "," + ehash2.encode("hex") + "," + IV2.encode("hex")
        self.send(send2)
        
        # Receive E(h(msgs, "CLNT", sharedSecret), (g^ab)modp)
        recv3 = self.recv()
        recv3Components = recv3.split(",")
        if len(recv3Components) != 2:
            print("Handshake error: Received invalid number of message components: {}".format(len(recv2Components)))
            return False
        
        ehash3 = recv3Components[0].decode("hex")
        IV3 = recv3Components[1].decode("hex")
            
        self.TRACE("3 Recv:\nehash3: {}\nIV3: {}\n".format(ehash3, IV3))
        hash3 = Cryptography.hash(recv1 + send2 + "CLNT" + str(self.sharedSecret))
        verifyEhash3 = Cryptography.symmetricKeyEncrypt(self.sessionKey, IV3, hash3)
        self.TRACE("Verifying hash: {}\n".format(verifyEhash3))
        if ehash3 != verifyEhash3:
            print("Error: Unexpected ehash3")
            return False
        
        print("Handshake esablished")
        self.TRACE("Session Key: {}".format(binascii.hexlify(self.sessionKey)))
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
        '--verbose',
        '-v',
        action="store_true",
        help="Display handshaking")

    args = parser.parse_args()
    
    server = Server(portNum = args.port, verbose = args.verbose)
    server.run()