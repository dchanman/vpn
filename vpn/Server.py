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
        
        ########################################################################
        # MESSAGE 1
        # Receive p, g, (g^a)modp and RandomA
        ########################################################################
        recv1 = self.recv(8000000)
        recv1Components = recv1.split(",")
        if len(recv1Components) != 4:
            print("Handshake error: Invalid number of message components: {}".format(len(recv1Components)))
            print("len: {}".format(len(recv1)))
            return False
            
        p = int(recv1Components[0])
        g = int(recv1Components[1])
        gamodp = int(recv1Components[2])
        nonce = recv1Components[3].decode("hex")
        self.TRACE("1 Recv:\n p: {}\n g: {}\n (g^a)modp: {}\n nonce: {}\n".format(
            p,
            g,
            gamodp,
            nonce.encode("hex"))
        )
        
        ########################################################################
        # DIFFIE-HELLMAN
        # Generate Diffie Hellman b
        # Compute (g^b)modp
        # Compute ((g^a)modp)^b
        ########################################################################
        b = Cryptography.generateRandomNumber()
        gbmodp = (g % p) ** b
        self.TRACE("Diffie Hellman Parameters:\n p: {}\n g: {}\n b: {}\n".format(
            p,
            g,
            b)
        )
        
        # Calculate session key
        gabmodp = gamodp ** b
        self.sessionKey = Cryptography.hash(str(gabmodp))[:Cryptography.SYMMETRIC_KEY_BLOCK_SIZE]
        self.TRACE("Session Key: {}\n".format(self.sessionKey))
        
        ########################################################################
        # MESSAGE 2
        # Send (g^b)modp, E(h(recv1, SRVR, self.sharedSecret), (g^ab)modp), IV
        ########################################################################
        IV2 = Cryptography.generateRandomIV()
        hash2 = Cryptography.hash(recv1 + "SRVR" + str(self.sharedSecret))
        ehash2 = Cryptography.symmetricKeyEncrypt(self.sessionKey, IV2, hash2)
        self.TRACE("2 Send:\n (g^b)modp: {}\n ehash2: {}\n IV2: {}".format(
            gbmodp,
            ehash2.encode("hex"),
            IV2.encode("hex"))
        )
        send2 = str(gbmodp) + "," + ehash2.encode("hex") + "," + IV2.encode("hex")
        self.send(send2)
        
        ########################################################################
        # MESSAGE 3
        # Receive E(h(msgs, "CLNT", sharedSecret), (g^ab)modp)
        ########################################################################
        recv3 = self.recv()
        recv3Components = recv3.split(",")
        if len(recv3Components) != 2:
            print("Handshake error: Received invalid number of message components: {}".format(len(recv2Components)))
            return False
        
        ehash3 = recv3Components[0].decode("hex")
        IV3 = recv3Components[1].decode("hex")
            
        self.TRACE("3 Recv:\n ehash3: {}\n IV3: {}\n".format(
            ehash3.encode("hex"),
            IV3.encode("hex"))
        )
        hash3 = Cryptography.hash(recv1 + send2 + "CLNT" + str(self.sharedSecret))
        verifyEhash3 = Cryptography.symmetricKeyEncrypt(self.sessionKey, IV3, hash3)
        self.TRACE("Verifying hash: {}\n".format(verifyEhash3.encode("hex")))
        if ehash3 != verifyEhash3:
            print("Error: Unexpected ehash3")
            return False
        
        ########################################################################
        # Key Exchange complete
        ########################################################################
        print("Session key established")
        self.TRACE("Session Key: {}\n".format(self.sessionKey))
        self.cumulativeHmac = Cryptography.hash(recv1 + send2 + recv3)
        
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