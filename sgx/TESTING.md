# SGX Testing and Demo

## SGX Testing

Running
```
make test
```
will execute a limited set of unit tests for the kmyth SGX functionality. These tests require both ```libkmip``` and ```libkmyth``` be installed.

Running
```
make clean
```
will remove all build artifacts.

## ECDH Key Exchange Demo with SGX

There are two sets of demo software. The first will complete  
an ECDH key agreement between software running within an SGX enclave and software  
running outside trusted hardware. The second demonstration consists of sample code  
for testing a client/server connection using Kmyth libraries. These demonstrations  
exist to show how Kmyth can be used to accomplish these goals, but they are not  
intended for any uses beyond demonstration and testing.  

To run these demonstrations, please be sure that Kmyth has been built and installed  
on your system.  

### ECDH Key Exchange with SGX

Use make to automatically run the demo with the SGX client and the separate key server program:
```
make demo
```

### ECDHE Test Key Server

This section describes the build process for the test server contained under the  
kmyth/sgx/demo/server directory.

This server is intended for test purposes only. It exists to demonstrate the key  
retrieval mechanisms in Kmyth. The demo client that builds alongside the server does  
not use any trusted hardware. For key retrieval using trusted hardware, the root Kmyth  
README and the kmyth/sgx README should be consulted. The demo client and the demo server   
should only be used for testing and demonstration purpose. For those seeking a more  
capable server, [OpenKMIP](https://github.com/OpenKMIP) may provide better options.  

This test key server was created for use with the Kmyth ECDHE SGX demo application.  

The program supports both server and client functionality.  

First, the server and client complete an ECDHE key exchange to establish a shared session key.
Then the client makes a KMIP key request,
and the server responds with the operational key.
After that, both applications terminate.
The test is successful if the session key and operational key
are the same for both the client and server.
(The keys are printed as log messages.)


#### Build

Before building, install libkmyth, libkmip, and the SGX SDK,
and add both to the dynamic linker configuration (ldconfig).

To build the program and generate new test keys:
```
make pre bin/ecdh-server bin/ecdh-client
cd data
bash gen_test_keys_certs.bash
```

#### Usage

To run as a key server (all arguments are required):
```
./bin/ecdh-server -r data/server_priv_test.pem -u data/client_cert_test.pem -p 7000
```

To run as a client application (all arguments are required):
```
./bin/ecdh-client -r data/client_priv_test.pem -u data/server_cert_test.pem -i localhost -p 7000
```

The client application should only be started after the server is already running.


#### Key Sharing Protocol

The test server uses TCP for network communications.
The port number is configurable.

The client always shares its signed ephemeral public key first,
then the server does the same.

The key sharing messages are in a custom format containing:
* the ephemeral public key point in octet string format
* a signature digest for the octet string, signed by the persistent private key
