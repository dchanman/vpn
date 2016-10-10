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
        
        # Send Encrypted Session Key and RandomA
        self.sessionKey = Cryptography.generateSymmetricKey()
        iv = Cryptography.generateRandomIV()
        encryptedSessionKey = Cryptography.symmetricKeyEncrypt(self.sharedSecret, iv, self.sessionKey)
                
        RA = Cryptography.generateNonce()
        self.TRACE("1 Send:\niv: {}\nencryptedSessionKey: {}\nnonceA: {}\n".format(
            binascii.hexlify(iv),
            binascii.hexlify(encryptedSessionKey),
            binascii.hexlify(RA))
        )
        send1 = iv + encryptedSessionKey + RA
        self.send(send1)
                        
        # Wait for reply: RandomB, h(msg, "SRVR", sharedSecret)
        recv1 = self.recv(1024)
        RB = recv1[:Cryptography.NONCE_SIZE]
        hash1 = recv1[Cryptography.NONCE_SIZE:]
        self.TRACE("2 Recv:\nnonceB: {}\nhash1: {}\n".format(
            binascii.hexlify(RB),
            hash1)
        )
        verifyHash1 = Cryptography.hash(send1 + "SRVR" + str(self.sharedSecret))
        
        self.TRACE("Verifying hash: {}\n".format(verifyHash1))
        if hash1 != verifyHash1:
            self.TRACE("Error: Unexpected hash1")
            return False
            
        # Send h(msgs, "CLNT", sharedSecret)
        msg2 = send1 + recv1 + "CLNT" + str(self.sharedSecret)
        hash2 = Cryptography.hash(msg2)
        self.TRACE("3 Send:\nhash {}\n".format(hash2))
        self.send(hash2);
        
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