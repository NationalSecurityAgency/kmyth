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

## Retrieve Key into SGX Enclave Demonstration

The demo software will complete an ECDH key agreement between ECDH client code
running within an SGX enclave and ECDH server-side code running outside
trusted hardware. While the host running the ECDH server code could directly
and securely exchange a key request and response messages over a channel
encrypted using session key(s) mutually computed via the ECDH key agreement,
for this demo, we have chosen to use a 'TLS proxy' to bridge the key request
and response communications with a remote KMIP-like server over a TLS
connection.

This demonstration was created only to provide an example of securely fetching
a secret value (e.g., a cryptographic key) from a remote server into an SGX
enclave using kmyth. This code is not intended for any use beyond
demonstration and testing.  

To run this demonstration, please be sure that Kmyth has been built and installed  
on your system.

### Running the Demonstration Using 'make'

Use the GNU 'make' utility to automatically run the demo with the SGX client
and the separate key server program:

```
make demo
```

Again, running

```
make clean
```

will remove all build artifacts.

### TLS Test (Demonstration) Key Server

This section describes the build process for the much simplified 'demo' server
contained under the kmyth/sgx/demo directory
(kmyth/sgx/demo/src/node/demo_kmip_server.c and
kmyth/sgx/demo/include/node/demo_kmip_server.h).

This 'demo' server is intended for test purposes only. It exists to demonstrate
the key retrieval mechanisms in Kmyth. For key retrieval using trusted
hardware, the root Kmyth README and the kmyth/sgx README should be consulted.
The demo server simply returns a fixed, demonstration key and should only be
used for testing and demonstration purposes. For those seeking a more capable
server, [OpenKMIP](https://github.com/OpenKMIP) may provide better options.

The 'demo' server accepts a KMIP 'get key' request from a TLS client (in the
case of the kmyth demonstration, a TLS proxy), and the server responds with a
KMIP 'get key' response containing a fixed, operational test key.

#### Build

Before building, install libkmyth, libkmip, and the SGX SDK,
and add them to the dynamic linker configuration (ldconfig).

To build the programs and generate new test keys:
```
make demo-all demo-test-keys-certs
```

#### Usage

To run as a 'demo' key server (all arguments are required):

```
./demo/bin/demo-kmip-server -k TLS_LOCAL_KEY -c TLS_LOCAL_CERT
                            -C TLS_REMOTE_CA_CERT -p TLS_PORT
```

The key and cert arguments must be file paths for elliptic curve keys
in PEM format.

The TLS remote CA cert is used to authenticate the remote client.
It must be part of the remote client certificate's chain of trust.

The 'demo server' uses TCP for network communications.
The port number is configurable.

Any TLS client application used to connect to this 'demo server' should only
be started after the 'demo server' is already running.


### ECDH/TLS Proxy Application

In addition to the KMIP-based 'demo' key server, the kmyth 'retrieve key'
demonstration includes a proxy application supporting connections
from the client program running within an SGX enclave to any remote TLS
service.

This proxy is also intended for test purposes only. It functions as a
man-in-the-middle, so all message payloads are visible to the proxy,
which does not use trusted hardware to protect data in use.
The proxy should only be used for testing and demonstration purposes.

The proxy provides an ECDH server connection and a TLS client connection.
It implements the 'retrieve key' protocol, described at a high level below,
over its ECDH connection with the SGX enclave client. It emulates an interface
with a remote KMIP key server over its TLS connection. Overall, it supports
retrieving a demonstration key value that is requested by the enclave client
from the remote 'demo server' and returning it to the enclave client.

#### Usage

The proxy usage is similar to the test key server application.

```
./demo/bin/tls-proxy -r ECDH_LOCAL_KEY -c ECDH_LOCAL_CERT -u ECDH_REMOTE_CERT
                     -p ECDH_LOCAL_PORT -I TLS_REMOTE_HOST -P TLS_REMOTE_PORT
                     -C TLS_REMOTE_CA_CERT -R TLS_LOCAL_KEY -U TLS_LOCAL_CERT
                     -m ECDH_SESSION_LIMIT
```

The key and cert arguments must be file paths for elliptic curve keys
in PEM format.

The ECDH key and cert are used for the ECDH key exchange.
They must be the keypair complements of the key and cert used by the
ECDH client application.

The TLS remote CA cert is used to authenticate the remote server.
It must be part of the remote server certificate's chain of trust.

The TLS local key and cert keypair are used for TLS client authentication,
which is required some but not all TLS services.
When client authentication is used, the local cert should be signed by a
Certificate Authority that is trusted by the remote server.

The proxy uses TCP for network communications. The port number is configurable.


#### 'Retrieve Key' Protocol

Kmyth includes functionality for retrieving a key from a remote server
(e.g., a KMIP server) into the enclave. Although key servers generally require TLS,
we did not implement a TLS client within the enclave in order to avoid potential
licensing issues with our open source code. Instead, we implemented a standalone TLS proxy
to support encrypted communications using ECDH between the enclave and proxy
and TLS between the proxy and key server.
The proxy runs in untrusted code, but it could reside in an environment
providing other enhanced protections.

The three-way protocol used for this
demonstration exchanges the following set of ordered messages:

The client sends a "client hello" message containing the client's identity
and the client's ephemeral public key, signed by the client's long-term
signing key.

The proxy returns a "server hello" message containing the proxy's identity,
the proxy's ephemeral public key, and the proxy's ephemeral public key,
signed by the proxy's long-term signing key.

Client and server (proxy) derive the ECDH ephemeral key as a shared secret
and run this through a key derivation function (KDF) using the two 'Hello'
messages (containing identification and public ephemeral values for both
peers) as "additional info" to produce a 512 bit (64 byte) result.

The client sends a "key request" message, packaging a KMIP 'get key' request
along with the server-side (proxy) ephemeral public key. This message is
encrypted with the first 256 bits of the 512-bit mutually derived 'key' value.
The encrypted message (ciphertext) is signed by the client's long-term signing
key.

The proxy uses the KMIP 'get key' request included in the "key request"
message received from the client to obtain a KMIP 'get key' response from a
server (in the case of the provided demonstration, a much simplified
'demo server'). The proxy then packages this KMIP 'get key' response into a
"key response" message, encrypts it using the last 256 bits of the 512-bit
derived key value. The encrypted message (ciphertext) is signed using the
server-side (proxy's) long-term signing key.
