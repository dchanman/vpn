# Host
The `Host` module is meant to be a base class for our future client/server modules which will each implement a different side of a key-sharing protocol. This module encapsulates the basic socket methods.

## Testing

On one terminal, run:
```
$ ./Host.py server
```

On another, run:
```
$ ./Host.py client
```

You're now connected and chatting to yourself!