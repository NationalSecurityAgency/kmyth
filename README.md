Kmyth is a project about distributed key management using cryptography and trusted hardware. Currently, Kmyth provides a simple mechanism for interacting with the TPM. The three core components are:  
    
* kmyth-seal: A tool that encrypts a file and protects the encryption key by sealing it to the TPM
* kmyth-unseal: A tool that reads a file (.ski) that has been kmyth-sealed and produces the original content
* kmyth-getkey: A tool that demonstrates the programatic api of kmyth-seal and kmyth-unseal by protecting a certificate private key used in a TLS connection

For more detailed information, please see the README under the tpm2 directory.
