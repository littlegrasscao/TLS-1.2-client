Project: TLS client

I used Python3:
Command to run: python3 .\TLS_client.py <server_ip> <port>
For example, python3 .\TLS_client.py localhost 44330

Note: Be sure to open an openssl s_server!
openssl s_server -dhparam dhparams.pem -key key.pem -cert cert.pem -accept 44330

generate pem files:
1. openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
2. openssl dhparam -out dhparams.pem 1024



Leave message:
I have successfully done all the client steps including sending Client Hello, analyzing Server Hello, verifying Server Certificate, verifying Server Signature, generating client DH key, master secret and session keys, sending out client finish and receive Server finish. 
At the end, the client will print "Server Finished message successfully received" and close the connection.

#if you generate a cert.pem using openssl immediately before running the program, verify certificate time could fail becuase openssl generates a time five hours after "now".
#add one day to now() make time verify pass
