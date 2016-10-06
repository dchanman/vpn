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
        self.send(sessionID)
        self.send(RA)
                        
        # Wait for reply: RandomB, h(msg, "SRVR", sharedSecret)
        RB = self.recv()
        hash1 = self.recv();
        msg = str(sessionID) + " " + str(RA) + " SRVR " + str(self.sharedSecret) 
        if hash1 != Cryptography.hash(msg):        
            return false
            
        # Send h(msgs, "CLNT", sharedSecret)
        msg2 = str(RB) + hash1 + " CLNT " + str(self.sharedSecret)
        self.send(Cryptography.hash(msg2));
        
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
            client.send(msg)
            reply = client.recv()
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