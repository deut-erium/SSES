# Secure Script Execution Server
Concurrent server to execute only signed client scripts 

## Build instructions
To build the server and/or client, libssl and gcc must be installed
```bash
sudo apt-get install build-essential libssl-dev
```

Once the packages are installed, navigate to the root of the project
(path containing `makefile`) and run

```bash
make
```

This will generate the `bin` and `build` directories, compile the sources, and create the client and server executables inside the bin directory.

## Running the server
After building the source, run the server in `bin/server`  
It exepectes 1 argument for path of either
1. An x509 certificate to verify the signatures with e.g
```bash
./bin/server certificates/example.crt
```
2. Or path to a directory containing x509 signatures which server reads 
non-recursively to verify the signatures e.g.  
```bash
./bin/server certificates
```

## Running the client
To send a script locally to the server, run the client with the path to the signed script
```bash
./bin/client example_signed_script.sh
```

## Communication Protocol
The communication used by client and server is via sockets.  
The server listens on port 8080 for concurrent clients.  

### Messaging protocol employed
We define a message structure of `1024` bytes, containing `1022` bytes of data and `2` bytes to indicate the length of the data

When a sender intends to send `n` bytes of data, he will form chunks of `1022` bytes each along with the length transmitted.
A message with length field 0 indicates a null packet and hence the reciever is notified when to stop recieving more data  

Based on the message structure, The sender and reciever implement 2 functions
`send_data(termination)` and `recv_all`  
`recv_all` will keep on socket `recv`ing 1024 bytes till it gets a null message.
`send_data` has 2 modes, with termination and without termination.
If data is transmitted with `send_data` with termination, the sender sends an empty message in the end to indicate reciever to stop `recv`ing  
Whereas when the sender is unsure about the length of data being sent, they can use `send_data` without termination so that reciever can keep on recieving data as long as sender has something to send.


### IPC protocol


|                                                  Server | Client                                              |
|                                                -------- | --------                                            |
|                                    Listens on port 8080 |                                                     |
|                                                         | Connect to port 8080                                |
|                                                         | Send signed script via `send_data` with termination |
|                                       Receives all data |                                                     |
|                                      Verifies signature |                                                     |
|                                  If verification fails, |                                                     |
| send_data with termination the failure status to client |                                                     |
|                               If verification succeeds, |                                                     |
|    send verification success status without termination |                                                     |
|                                  Begin script execution |                                                     |
|                   and send_data script output in chunks |                                                     |
|            Send termination after script execution ends |                                                     |
|                                                         | Client receives all data and exits after end        |


### Client Script format
The signature is base64 encoded (with no newlines in between) and prepended with a comment `#` (to ensure scripts can be executed otherwise) as the first line of the script  
As shown in this template
```
#[BASE64 ENCODED SIGNATURE][newline]
#!/bin/bash
[SCRIPT CONTENTS]
```
For example a script `hello_world.sh` with contents
```
#!/bin/bash

echo "hello world"
```
will look like 
```
#LYCxhc0B0J4U7xEfJi7qGT+lBdgs4SWbRXOgt3GlaHD4g8s7EPgigCZ6jbl9NDeQAPiutNRs+K5tecQpASWFhQobDZHGT6MGQSCbVKRuY4XD9UiL40WOjgZ1qOgLf1idUN556yL/BXAaDD/fW4TaCSYOfIVOZro8rbF+071OULv44+OtjreEgzSrpLs4AvTKMaGkQvZ563ox1ThgYDTq3Y+9Wm2shcymWGYKlJluCueSO0aRJlgJxMfwEThVVJSRkpTABOdVp7Olx50KPJePqE96VM39pX/GYHfvU7ukHnHaTCFarY+wCvqcQRKX1LUaZSG5DW051HrTocTen9k7sQ==
#!/bin/bash

echo "hello world"
```
After signing

### Helper Scripts
#### generate_cert.sh
This script generates a self-signed SSL/TLS certificate and extracts the public key from it. It takes three arguments: the path for the output certificate file, the path for the output private key file, and the path for the output public key file. 


#### verify_sign.sh
A bash script that verifies the digital signature of a signed script file using a specified public key. The script takes two arguments: the path to the signed script file and the path to the public key file.

#### sign_script.sh
This script takes three arguments: the path to a script file, the path to a private key file, and the path to an output file. The script signs the contents of the input script file using the private key and appends the signature to the beginning of the output file, prefixed with a "#" character. The script file itself is then appended to the output file. The resulting output file can be verified using the public key corresponding to the private key used for signing.

## Status code of execution
### Outputs of the server
The server sends the details of connection status with a client to the stderr
- List of loaded certificates
- Connection accepted, signature verification status
- Connection close status

Rest of the errror messages are directed to stderr


### Exit codes
- argc != 2:
  - Status code: EXIT_FAILURE
  - Explanation: This indicates that the server was not invoked with the correct number of command-line arguments, second argument should be the certificate path

- socket() fails:
  - Status code: EXIT_FAILURE
  - Explanation: This indicates that the server was unable to create a socket to listen for incoming connections.

- setsockopt() fails:
  - Status code: EXIT_FAILURE
  - Explanation: This indicates that there was an error in setting socket options.

- bind() fails:
  - Status code: EXIT_FAILURE
  - Explanation: This indicates that there was an error in binding the socket to the specified address and port.

- get_pubkeys() fails:
  - Status code: EXIT_FAILURE
  - Explanation: This indicates that there was an error in extracting public keys from the path given

- accept() fails:
  - Status code: EXIT_FAILURE
  - Explanation: This indicates that there was an error in accepting an incoming connection.

- pthread_create() fails:
  - Status code: EXIT_FAILURE
  - Explanation: This indicates that there was an error in creating a new thread to handle a client connection.

- pthread_detach() fails:
  - Status code: EXIT_FAILURE
  - Explanation: This indicates that there was an error in detaching a thread.

- Successful execution:
  - Status code: 0
  - Explanation: This indicates that the server has successfully started listening for incoming connections and has spawned threads to handle them.
