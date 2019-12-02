# kmyth

Kmyth is a project about distributed key management using cryptography and specialized, commodity hardware. The long-term goal of this project is to design and prototype a secure distributed key management system. While this system is expected to evolve over time, the initial efforts involve enabling access to the [Trusted Platform Module](https://en.wikipedia.org/wiki/Trusted_Platform_Module) (TPM) for users wanting to protect keys with trusted hardware. The current version of kmyth reflects this by emphasizing access to the TPM. Specifically, we simplify the process of using a TPM to encrypt/decrypt a file through sealing and unsealing within the TPM. Additionally, we provide an example use of the encrypted file to perform a task (see: [Usage](#usage)).   

Kmyth is a research project and a proof-of-concept prototype. It is intended to be used for testing and development. It is not intended for production use. Some firmware or configuration updates (e.g. the BIOS) can cause a denial of service by causing PCR measurements to change. This will cause a permanent loss of encrypted data.  

**We will not be adding any new features to Kmyth for TPM 1.2. The current tool uses TrouSerS (TSS) to interface with the TPM. TSS depends on OpenSSL 1.0.2, which will no longer be supported after December 31, 2019. We intend to respond to routine requests, such as those for clarification or identifying bugs in the code. We plan to provide support until Kmyth for TPM 2.0 is made available.**

----
Table of Contents  

  * [Requirements](#requirements)
  * [Installation](#installation)
    * [Dependencies](#dependencies)
    * [Building](#building)
  * [Usage](#usage)
  * [TPM-Tips](#tpm-tips)
  * [Random-Sources](#random-sources)

----
## Requirements

* TPM version 1.2.
* TPM must be enabled.
* TPM must be configured using the well-known secret and have a storage root key.
   * If you're not sure, or if things aren't working, check [TPM-Tips](#tpm-tips).

----
## Installation

### Dependencies

Required for building kmyth:
* gcc
* glibc
* trousers
* trousers-devel
* tpm-tools
* libffi-devel
* indent
* openssl version 1.0.2 -- the [OpenSSL LTS version](https://www.openssl.org/policies/releasestrat.html).
* openssl-devel version 1.0.2

On CentOS 7 these can be installed with
```
yum install openssl openssl-devel glibc gcc trousers-devel trousers tpm-tools libffi-devel indent
```

Required for running unit tests:
* CUnit
* Cunit-devel

On CentOS 7 these can be installed with
```
yum install CUnit CUnit-devel   
```

#### Preliminaries for kmyth-getkey  

In order to use kmyth-getkey, additional setup is required:
  * An operational key server must be running on the network.
  * The key you wish to acquire must exist on the key server.
  * Both the machine running the kmyth tool and the server must possess a certficate signed by a trusted CA.
    1. The client's certificate must be signed by a trusted CA.
    2. The server's certificate must be signed by a trusted CA.
    3. The client must have access to the server's public certificate (.crt).
  * The private portion of the client's certificate (.pem) must be sealed by the machine using kmyth-seal.

### Building

Once the dependencies are installed:
1. Acquire the code -- copy/paste into terminal: git clone git@github.com/something/kmyth.git  
2. In the KMYTH directory run ```make``` then run ```make install```
  * By default kmyth installs to ```/usr/local/bin``` but this can be overridden by using the ```make install PREFIX=<destination>``` which will install kmyth in ```<destination>/bin```

----
## Usage

### kmyth-seal

This tool will seal a file using the TPM. 
  * WARNING: Because the TPM is used to seal the symmetric key that encrypts your data, the encrypted data can only be decrypted using the same machine (and the same TPM) with which it was encrypted. If the data is moved to a different machine, if the PCRs used to encrypt it change, or if the TPM is reset, the data will be lost permenantly.

#### kmyth-seal usage

    usage: ./kmyth-seal [options] 
    options are: 
     -i or --input        : Path to file containing data to be encrypted
     -o or --output       : Ouput file path, if none given will overwrite input file
     -p or --pcrs_list    : List of PCRS, defaults to none. Encapsulate in quotes, e.g. "0, 1, 2"
     -c or --cipher       : Specifies the cipher type to use. Defaults to AES/GCM/NoPadding/256
     -v or --verbose      : Adds print statements to help with debugging
     -h or --help         : help
     -l or --list_ciphers : Lists all valid ciphers and exits.


    -i or --input : Path to file containing data to be encrypted
    This is the file to be encrypted. This file will be overwritten unless a different output file is selected.

    -o or --output : Ouput file path, if none given will overwrite input file
    This specifies the destination of the encrypted data. If none is given, it is assumed that -o will be the same file used for the input. If another path is given, the original input file will remain intact and a new, encrypted version will be created.

    -p or --pcrs_list : List of PCRS, defaults to none. Encapsulate in quotes, e.g. "0, 1, 2"
    Adds a set of PCRs to the sealing operation. Their state must be the same for unsealing as it was when the data was sealed.

    -c or --cipher : Specifies the cipher to use
    If unspecified, AES/GCM/NoPadding/256 will be used, See list_ciphers for the full list of implemented ciphers.

    -l or --list_ciphers : Lists all valid ciphers
    Provides list of available cipher options for --cipher

    -v or --verbose : Adds print statements to help with debuging
    This adds an abundance of text concerning the activities of the seal process, especially the TPM interactions.

    -h or --help : help
    Displays the command line options.


### kmyth-unseal

This tool will unseal a file which has been sealed using the TPM.

#### kmyth-unseal usage

    usage: ./kmyth-unseal [options]
    options are:
     -i or --input    : Path to file containing data to be decrypted
     -o or --output   : Ouput file path, if none given will overwrite input file
     -s or --standard : Output decrypted result to standard out, overrides output file
     -v or --verbose  : Adds print statements to help with debuging
     -h or --help     : help


    -i or --input : Path to file containing data to be decrypted
    This is the file be decrypted. This file will be overwritten unless a different output file is selected.

    -o or --output : Ouput file path, if none given will overwrite input file
    This specifies the destination of the decrypted data. If none is given, it is assumed that -o will be the same file used for the input. If another path is given, the original input file will remain in tact and a new, decrypted version will be created.

    -s or --standard : Output decrypted result to standard out, overrides output file
    This specifies that the destination of the decrypted data should be to stdout instead of to a file. If this is selected in conjunction with -o, the output file will be ignored and the contents will instead be directed to stdout.

    -v or --verbose : Adds print statements to help with debuging

    -h or --help : help
    Displays the command line options.

### kmyth-getkey

This tool is used for obtaining a key from a remote key server. While kmyth can be used to protect other data for different uses, this program facilitates key retrieval by implementing a kmyth backed client that interacts with a key server. Kmyth-getkey will authenticate the server, and it provides its own certificate so the server can mutually authenticate.

#### Preliminaries

Kmyth assumes a key server has been established and already possesses a key you wish to acquire. 

In order to use kmyth-getkey some preliminary setup is required:  
  * An operational key server is running on the network.
  * The key you wish to acquire is on the key server.
  * The machine running the kmyth tool has been enrolled in an established PKI with the key server.  
    1. The client's certificate has been signed by a trusted CA.  
    2. The server's certificate has been signed by a trusted CA.  
    3. The client has access to the server's public certificate (.crt).  
  * The private portion of the client's certificate (.pem) has been sealed by the machine using kmyth-seal.  

#### kmyth-getkey usage

    usage: ./kmyth-getkey [options]
    options are:

     Client Certificate information --
     -i or --input  : Path to file containing the sealed client's certificate private key
     -l or --client : Path to file containing the client's certificate

     Server information --
     -s or --server  : Path to file containing the server's certificate
     -a or --address : The ip_address:port for the TLS connection
     -m or --message : An optional message to send the key server

     Output information --
     -o or --output   : Ouput file path to write the key. If none is selected, key will be sent to stdout

     Misc --
     -v or --verbose : Adds print statements to help with debuging
     -h or --help  : help

---
## TPM-Tips

If on Centos, run:  

    sudo yum install trousers trousers-devel tpm-tools  

If nothing was installed, see if you can view the TPM by running:  

    tpm_version

If you get a communication failure OR you had to install trousers and tpm-tools, run:  

    sudo tcsd start

Then, again, run:  

    tpm_version

If you still get a communication failure, you will need to restart your machine. In the BIOS (usually under 'security' or related), look for the TPM and "Enable TPM"  

Once restarted, again start the service:  

    sudo tcsd start

Then the command:  

    tpm_version

Should work and show the version. If it does, take ownership of the TPM by:  

    tpm_takeownership -yz

The -yz will set the passwords to the well-known secret (20 bytes of 0x00).  

At this point, you should be good to go for using KMYTH.

----
## Security Guidance

### Random-Sources

 The most reliable and available  source of random on a commercial machine is the kernel entropy accumulator. On modern UNIX/Linux machine this takes the form of /dev/random and /dev/urandom. These random sources have the advantage of being able to collect entropy from a variety of sources only available to the kernel. If correctly configured they can carry entropy across a reboot cycle. 

 We use OpenSSL's RAND_bytes to generate our client wrapping key. It seeds from /dev/urandom.

 The user should be aware of the slow start issue present in kernel entropy accumulators. When a random number generator (RNG) is first configured, it has very little information available which cannot be guessed. Various mitigations for this problem are available, among them, writing a fresh random seed from some known good source to the entropy accumulator by writing to /dev/random. As the RNG continues to run, and more system input is fed in (interrupt timings, packet data, keyboard activity,...), anyone who is not in a position to see all of the input will eventually lose track of the internal state of the RNG.
 
### Local Storage of Sensitive Material
 
 For some applications, sensitive material must be available through the operating system's file IO interface; for example, one may need operational key accesible to processes that expect to read key material from a file.
 One option for limiting the exposure of sensitive material is to store it in a file in the ramfs RAM file system. We do not recommend the tmpfs RAM file system, because tmpfs may use swap space.
