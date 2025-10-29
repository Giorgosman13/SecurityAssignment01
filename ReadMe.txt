Assignment 01
Students : Giorgos Vassalos     2022030052
           Asterios Agiannis    2022030164

In this project we have a client server handshake that depends on a certificate which both parties have.
If the certificate of the cliet is verified by the SSL server then the handshake is completed and the client and server can share encrypted messages. (./client)
However if it is not then the handshake fails and the connection between client and server is aborted. (./rclient).
When the server and client are connected it asks the client for a username and password.
The only username / password combo allowed is: sousi / 123.
Inputting a correct or not username / password combo will result to the according message.
The commands we run to get this project to work are: 
first: ./server 8082
Of which the number 8082 is the port of our pc where the server will run.
We can't run it on ports 80,443,124 since they require being the root to run off of them.
If we sudo run the command then we can run it also from those ports.

Then after the server is set up we run: ./client 127.0.0.1 8082
Where 127.0.0.1 is the localhost IP which tries to connect to a server running from the same machine and 8082 is the port that the server is located.
If the connection is successful then the client gets asked by the server for the username and password
If its correct then we get a valid server response 
If its wrong then we get an "Invalid Message" response

To check what happens if someone tries to connect with a rogue client which has different certificates than the server we do:
./rclient 127.0.0.1 8082

Which instantly returns an error code to both the server and the client and the message "peer did not return a certificate or returned an invalid one”

The commands we run to get the certificates for each are:

1. Generating a Certificate Authority to use for both the server and client
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout ca.key -out ca.crt -subj "/C=GR/ST=Crete/L=Chania/O=TechnicalUniversityofCrete/OU=ECE Lab/CN=RootCA"

req is that we request for the generation of a file
-x509 the type of certificate (an X509 certificate)
-nodes no encryption of the private key with a password
-days 365 the certificate will be available and valid for 1 year
-newkey rsa:2048 generation of a pair of 2048 bit rsa keys.
-keyout ca.key the certificate key will be inputted in the ca.key file
-out ca.crt the certificate will be on the ca.crt file
-subj "----" is a specification of the subject fields.

2. Generating Server Certificate signed by CA

# 1. Create server key and CSR 
openssl req -new -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/C=GR/ST=Crete/L=Chania/O=TechnicalUniversityofCrete/OU=ECE Lab/CN=localhost" 
 
req is that we request for the generation of a file
-new generates new key and certificate request
-newkey rsa:2048 will generate a pair of rsa keys of 2048 bits
-nodes no encryption of the private key with a password
-keyout server.key the server key will be inputted in the server.key file
-out server.csr the server certificate signing request will be saved on server.csr
-subj "---" is a specification of the subject fields.


# 2. Sign with CA 
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -sha256 

x509 the type of the certificate
-req is that we request the generation of a file
-in server.csr the csr file to be signed
-CA ca.crt which certificate will sign the server.csr
-CAkey ca.kay the ca certificate key used to sign the certificate
-CAcreateserial requesting the creation of a serial file --> ca.srl
-out server.crt the output signed certificate file 
-days 365 the days for which the certificate will be valid
-sha256 the hashing algorithm used for the signature  

The same command parameters are used for the creation for both the client and the rogue client certificates.
However for the rogue client we generate a different ca with different -subj and use that for signing the csr file of the rogue client.
