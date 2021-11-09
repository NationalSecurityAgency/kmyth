# ECDHE Test Key Server

This test key server was created for use with the Kmyth ECDHE SGX demo application.

The program supports both server and client functionality.

First, the server and client complete an ECDHE key exchange to establish a shared session key.
Then the client makes a KMIP key request,
and the server responds with the operational key.
After that, both applications terminate.
The test is successful if the session key and operational key
are the same for both the client and server.
(The keys are printed as log messages.)


## Build

Before building, install libkmyth and the SGX SDK,
and add both to the dynamic linker configuration (ldconfig).

To build the program and generate new test keys:
```
cd sgx/demo
make pre bin/ecdh-server
cd data
./gen_test_keys_certs.bash
```

## Usage

To run as a key server (all arguments are required):
```
./bin/ecdh-server -r data/server_priv_test.pem -u data/client_cert_test.pem -p 7000
```

To run as a client application (all arguments are required):
```
./bin/ecdh-server -c -r data/client_priv_test.pem -u data/server_cert_test.pem -i localhost -p 7000
```

The client application should only be started after the server is already running.


## Key Sharing Protocol

The test server uses UDP for consistency with the other KMIP applications in Kmyth.
The network port is configurable.

After starting up, the server waits to receive an init message from the client.
This establishes the client address info used in all communications from the server to the client.

The client always shares its signed ephemeral public key first,
then the server does the same.

The key sharing messages are in a custom format containing:
* the ephemeral public key point in octet string format
* a signature digest for the octet string, signed by the persistent private key
