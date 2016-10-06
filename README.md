# VPN

This is a small VPN program that allows a client and a server program talk to one another.

# Setup

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

## Handshake

Our key establishment protocol is based on the SSL Connection Protocol. This protocol takes place after a client and a server have already established a *session key*. 

We assumes that both client and server have a *sharedSecret* that no other party can access. We will use this shared secret as if it were the SSL *session key*.

### Steps
1. Client: Send a randomly generated **session-id** as well as a random number **R<sub>A</sub>**.
2. Server: Replies with the same **session-id**, another random number **R<sub>B</sub>**, and the hash *h(message1, "SRVR", sharedSecret)*
3. Client: Replies with the hash *h(mesage1, message2, "CLNT", sharedSecret)*

At this point, both client and server have established a session-id. They use their *sharedSecret* to hash the session-id for seeding a random generator, and the output will be used to create their session key.

## Communication

Messages are encrypted with AES in CBC mode with a randomly generated IV and the session key. The complete message to be sent is *(IV, encrypted message)* and the *HMAC* of that message.