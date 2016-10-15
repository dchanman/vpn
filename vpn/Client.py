#!/usr/bin/env python
import Host
import Cryptography
import binascii

class Client(Host.Host):
    
    def __init__(self, ipAddr = "127.0.0.1", portNum = 32694, sharedSecret="iloveildar", padding=" ", verbose = False):
        while len(sharedSecret) < Cryptography.SYMMETRIC_KEY_KEY_SIZE:
            sharedSecret += padding
        super(Client, self).__init__(ipAddr, portNum, sharedSecret, verbose = verbose)
        
    def handshake(self):
        """
        Connect and start the handshake.
        Return true if connection and handshake are successful
        """
        self.initClient()
        
        # Generate Diffie Hellman g and p
        g = Cryptography.generateLargeRandomPrime()
        p = g
        # Make sure we don't accidentally generate the same prime...
        while p == g:
            p = Cryptography.generateLargeRandomPrime()
        
        # Generate secret integer a
        a = Cryptography.generateRandomNumber()
        
        # Calculate (g^a)modp
        gamodp = (g % p) ** a
        self.TRACE("p: {}\ng: {}\na: {}\ngmodp: {}".format(p, g, a, gamodp))
        
        # Send p, g, (g^a)modp, and RandomA
                
        RA = Cryptography.generateNonce()
        self.TRACE("1 Send:\np: {}\ng: {}\ngmodp: {}\nnonceA: {}\n".format(
            p,
            g,
            gamodp,
            binascii.hexlify(RA))
        )
        send1 = str(p) + "," 
        send1 += str(g) + "," 
        send1 += str(gamodp) + "," 
        send1 += binascii.hexlify(RA).decode("utf-8")
        self.TRACE("len: {}".format(len(send1)))
        self.send(send1.encode("utf-8"))
                        
        # Wait for reply: (g^b)modp, E(h(recv1, SRVR, self.sharedSecret), (g^ab)modp), IV
        recv2 = self.recv(8000000)
        recv2Components = recv2.split(",")
        if len(recv2Components) != 3:
            print("Handshake error: Received invalid number of message components: {}".format(len(recv2Components)))
            return False
        
        gbmodp = int(recv2Components[0])
        ehash2 = recv2Components[1].decode("hex")
        IV2 = recv2Components[2].decode("hex")
        self.TRACE("2 Recv:\ngbmodp: {}\n ehash2: {}\n IV: {}".format(
            gbmodp,
            ehash2.encode("hex"),
            IV2.encode("hex"))
        )
        
        # Calculate session key
        gabmodp = gbmodp ** a
        self.sessionKey = Cryptography.hash(str(gabmodp))[:Cryptography.SYMMETRIC_KEY_BLOCK_SIZE]
        self.TRACE("Session Key: {}\n".format(self.sessionKey))
        
        # Verify reply
        hash2 = Cryptography.hash(send1 + "SRVR" + str(self.sharedSecret))
        verifyEhash2 = Cryptography.symmetricKeyEncrypt(self.sessionKey, IV2, hash2)
        self.TRACE("Verifying hash: {}\n".format(verifyEhash2))
        if ehash2 != verifyEhash2:
            self.TRACE("Error: Unexpected hash2")
            return False
            
        # Send E(h(msgs, "CLNT", sharedSecret), (g^ab)modp)
        IV3 = Cryptography.generateRandomIV()
        msg3 = send1 + recv2 + "CLNT" + str(self.sharedSecret)
        hash3 = Cryptography.hash(msg3)
        ehash3 = Cryptography.symmetricKeyEncrypt(self.sessionKey, IV3, hash3)
        self.TRACE("3 Send:\nehash2 {}\nIV2: {}\n".format(ehash3, IV3))
        send3 = ehash3.encode("hex") + "," + IV3.encode("hex")
        self.send(send3);
        
        self.TRACE("Handshake esablished")
        self.TRACE("Session Key: {}".format(binascii.hexlify(self.sessionKey)))
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
        self.startChat()

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
    parser.add_argument(
        '--verbose',
        '-v',
        action="store_true",
        help="Display handshaking")

    args = parser.parse_args()
    
    client = Client(portNum = args.port, verbose = args.verbose)
    client.run()