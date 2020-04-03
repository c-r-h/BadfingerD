# BadfingerD

BadfingerD is a simple dæmon that responds to a TCP connection by 
running a shell command and returning the output.

BadfingerD listens for a TCP connection (on port 79 by default).  When 
it receives a connection, it ignores any input sent by the client.  
Instead, it executes a shell command and redirects the output back over 
the TCP connection.  It can be useful for querying in-home devices such 
as file servers, re-flashed access points, or such-like.

BadfingerD has been tested on a variety of Linux systems.  It should be 
portable to lots of other platforms as well, though it may need some 
minor fiddlement.

To compile (on Linux):
```
cc -o badfingerd badfingerd.c
```
For help:
```
badfingerd -h
```

That's all there is to it. 
