This code requires version 2.10 or later of the Intel SGX SDK, available
at https://github.com/intel/linux-sgx/

Ensure version 2.35 of GNU Binutils is installed and has precedence in your
$PATH in order to compile with the LVI mitigations.

Prior to build, you must create a private key to sign the enclave. It can be done with this command from the kmyth/sgx/ directory:

```bash
openssl genrsa -out Enclave/Enclave_private.pem -3 3072
```

To build a debug simulation version of the enclave, which will function on
platforms without support for SGX, use this command:

```bash
make SGX_MODE=SIM SGX_DEBUG=1 MITIGATION-CVE-2020-0551=NONE
```

You may need to add the directory containing `libsgxseal.so` to your
`LD_LIBRARY_PATH` before `demo` will run.  Try this command:
```bash
LD_LIBRARY_PATH=$PWD:$LD_LIBRARY_PATH ./demo
```
