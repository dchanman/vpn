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
        recv = self.recv()
        
        # Send reply: RandomB, h(msg, "SRVR", sharedSecret)
        
        # Receive h(msgs, "CLNT", sharedSecret)
        
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
            msg = self.recv()
            if len(msg) == 0:
                self.close()
                print("Client disconnected. Done.")
                return
            
            print("Received ({}): {}".format(len(msg), msg))
            # Echo the message
            self.send(msg)

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