# VPN

This is a small VPN program that allows a client and a server program talk to one another.

# Usage

In one terminal, run the following command
```
vpn/Server.py
```

In another terminal, run the following command
```
vpn/Client.py
```

## Optional Arguments

The following arguments work for both `Server` and `Client`:
### Verbose output

Display tracing output for all intermediate cryptographic operations. Note that this will display the session key in plain text.
```
vpn/Server.py -v
```

### Specify port

A known issue is that if the client closes the TCP connection, the port will continue to be locked after both client and server processes terminate. A workaround is to use a different port until the old port reaches a timeout.
```
vpn/Server.py 33333
```

# Environment Setup

## General Setup

We are using **Python 2.7** with the following packages installed:
* pycrypto v2.6.1

## Anaconda
If you are using Anaconda to sandbox your Python environment, you can install all required libraries by running the following:

```bash
conda env create -f anaconda_env.yml
```

Then switch to the new environment

```bash
source activate cpen442
```

## Installing Anaconda
Refer to the official guide [here](http://conda.pydata.org/docs/install/quick.html). It should only take 2 minutes.


# Protocol

## Cryptography Parameters
* Diffie-Hellman generator primes sizes (g, p): 16-bits
    * This is insecure in practice, but larger bitsizes would require a faster implementation to compute ((g^x)modp)^y
* Diffie-Hellman private number bitsizes (a, b): 8-bits
    * This is insecure in practice, but larger bitsizes would require a faster implementation to compute ((g^x)modp)^y
* AES block size: 32-bites
* AES mode: CBC
* HMAC algorithm: SHA256
* Nonce size: 32 bits

The session key is the first 32-bits from the SHA256 hash of the Diffie-Hellman shared key.

## Handshake

Our key establishment protocol is based on the SSL Connection Protocol and the Diffie-Hellman key exchange.

We assumes that both client and server have a *sharedSecret* that no other party can access. We will use this shared secret for mutual authentication.

### Steps
1. Client: Generate Diffie-Hellman parameters **g**, **p**, **a**. Compute **(g^a)modp**. Send "p, g, (g^a)modp, nonce"
2. Server: Generate Diffie-Hellman parameter **b**. Compute **(g^b)modp** and derive the session key from **(g^ab)modp**. Send "(g^b)modp, E(h(msg1, SRVR, sharedSecret), sessionKey), IV"
3. Client: Derive the session key from **(g^ab)modp**. Send "E(h(msg1, msg2, CLNT, sharedSecret), sessionKey), IV"

At this point, both client and server have established a session-key. The *cumulative HMAC* (explained more in the next section) is initialized to be the hash of *msg1, msg2, msg3, sharedSecret* that were sent in the handshake.

## Communication

Messages are encrypted with AES in CBC mode with a randomly generated IV and the session key. The complete message to be sent is *(IV, encrypted message)* and the *Cumulative HMAC* of all previous messages.

The new cumulative HMAC is the hash of the current HMAC (IV, encrypted message) concatenated with the old cumulative HMAC. The cumulative HMAC is updated whenever a message is sent or received by either client or server. This means that the cumulative HMAC is always in sync between client and server as long as no messages are in flight.