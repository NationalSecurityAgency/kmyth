# Kmyth

Kmyth provides a simple mechanism for interacting with the TPM. The
three core components are:
* kmyth-seal: A tool that encrypts a file and protects the encryption
  key by sealing it to the TPM
* kmyth-unseal: A tool that reads a file (.ski) that has been
  kmyth-sealed and produces the original content
* kmyth-getkey: A tool that demonstrates the programatic api of
  kmyth-seal and kmyth-unseal by protecting a certificate private key
  used in a TLS connection

In addition Kmyth provides a simple API which allows developers to use
the TPM without having to become experts in the underlying TPM
libraries.

----
Table of Contents  

  * [Building and Installation](#building-and-installation)

  * [Usage](#usage)

  * [TPM-Tips and Notes](#notes)

  * [Random-Sources](#random-sources)

----
## Building and Installation

For build and installation instructions see the [INSTALL](INSTALL.md) file.

----
## Usage

### kmyth-seal

This tool will *kmyth-seal* a file using the TPM 2.0. In TPM parlance,
'sealing' typically refers to encrypting the file using a key known only to
that TPM (i.e., binding that data to a specific TPM) and imposing system state
criteria (i.e., Platform Configuration Register or PCR constraints) on the
decryption of that data. While *kmyth-seal* utilizes the TPM's capability to
'seal' and/or 'bind' under the hood, it references the entire process used to
create a .ski file result. This includes:
* generation and use of a wrapping key to symmetrically encrypt the input data
* use of the TPM to derive the Kmyth SRK as a primary key 
* use of the TPM to create a Kmyth SK that is sealed to the SRK with an
authorization policy
* use of the TPM to seal the symmetric wrapping key to the SK and an
authorization policy
* compilation of the encrypted secret being protected (e.g., CAPK), TPM sealed
storage key, TPM sealed symmetric key, and the symmetric cipher specification
into a .ski file to facilitate the ability to later *kmyth-unseal* it

##### *WARNING:*
*Because the TPM is used to encrypt the symmetric key that encrypts your data,
the encrypted data can only be decrypted using the same machine (and the same
TPM) with which it was encrypted. If the data is moved to a different machine,
if the PCRs used to encrypt it change, or if the TPM is reset, the data will
be permanently lost.*

    usage: ./bin/kmyth-seal [options] 
    
    options are: 
    
     -a or --auth_string   String used to create 'authVal' digest. Defaults to empty string (all-zero digest).
     -i or --input         Path to file containing the data to be sealed.
     -o or --output        Destination path for the sealed file. Defaults to <filename>.ski in the CWD.
     -f or --force         Force the overwrite of an existing .ski file when using default output.
     -p or --pcrs_list     List of TPM platform configuration registers (PCRs) to apply to authorization policy.
                           Defaults to no PCRs specified. Encapsulate in quotes (e.g. "0, 1, 2").
     -c or --cipher        Specifies the cipher type to use. Defaults to 'AES/GCM/NoPadding/256'
     -l or --list_ciphers  Lists all valid ciphers and exits.
     -w or --owner_auth    TPM 2.0 storage (owner) hierarchy authorization. Defaults to emptyAuth to match TPM default.
     -v or --verbose       Enable detailed logging.
     -h or --help          Help (displays this usage).


### kmyth-unseal

This tool will *kmyth-unseal* a file using the TPM 2.0. In TPM parlance,
'unsealing' typically refers to decrypting 'sealed' input data using a key
known only to that TPM (i.e., the encrypted input is 'bound' to a specific TPM)
while imposing system state criteria (i.e., Platform Configuration Register or
PCR constraints) on the ability to decrypt. While *kmyth-unseal* utilizes the
TPM's capability to 'unseal' under the hood, it references the entire process
used to recover Kmyth protected secret data (e.g., a CAPK) from a .ski file
input. This includes:
* recovery of data contained in the input .ski file
* use of the TPM and its Kmyth SRK to recover the Kmyth SK
* loading the recovered Kmyth SK into the TPM
* use of the TPM and loaded Kmyth SK to recover the symmetric wrapping key
* use of the symmetric wrapping key and the cipher specification
to recover the 'kmyth-sealed' secret
* providing the recovered result to the user in the required format
(e.g., a file)  
```
    usage: ./bin/kmyth-unseal [options]
    
    options are: 
    
     -a or --auth_string   String used to create 'authVal' digest. Defaults to empty string (all-zero digest).
     -i or --input         Path to file containing data the to be unsealed
     -o or --output        Destination path for unsealed file. This or -s must be specified. Will not overwrite any
                           existing files unless the 'force' option is selected.
     -s or --stdout        Output unencrypted result to stdout instead of file.
     -w or --owner_auth    TPM 2.0 storage (owner) hierarchy authorization. Defaults to emptyAuth to match TPM default.
     -v or --verbose       Enable detailed logging.
     -h or --help          Help (displays this usage).
```

### kmyth-getkey

This tool is used specifically for obtaining a key from a remote server.

#### Preliminaries

In order to use _kmyth-getkey_ some preliminary setup is required.

* You must have a key server listening for connections.

* The client running _kmyth-getkey_ must have a private key sealed using
 _kmyth-seal_ along with a corresponding certificate.

* The key server must be able to authenticate the client's certificate.
```
    usage: ./bin/kmyth-getkey [options]
    
    options are:
    
    Client Information --
      -i or --input         Path to file containing the kmyth-sealed client's certificate private key.
      -l or --client        Path to file containing the client's certificate.
    
    Server Information --
      -s or --server        Path to file containing the certificate
                            for the CA that issued the server cert.
      -c or --conn_addr     The ip_address:port for the TLS connection.
      -m or --message       An optional message to send the key server.
    
    Output Parameters --
      -o or --output        Output file path to write the key. If none is selected, key will be sent to stdout.
    
    Sealed Key Parameters --
      -a or --auth_string   String used to create 'authVal' digest. Defaults to empty string (all-zero digest)
      -w or --owner_auth    TPM 2.0 storage (owner) hierarchy authorization. Defaults to emptyAuth to match TPM default.
    
    Misc --
      -v or --verbose       Detailed logging mode to help with debugging.
      -h or --help          Help (displays this usage).
```

---
## Notes

### General TPM 2.0

* TPM 2.0 Software Stack (TSS2)

  * The [Feature API (FAPI)](https://trustedcomputinggroup.org/resource/tss-feature-api-specification/)
  will eventually provide the highest-level of abstraction. This layer has
  not yet been implemented.

  * [The Enhanced System API (ESAPI)](https://trustedcomputinggroup.org/resource/tcg-tss-2-0-enhanced-system-api-esapi-specification/)
  is the next layer down. While less abstract than the FAPI, it hides much
  of the session management overhead and provides cryptographic function
  support. Our development efforts preceded the initial release of an
  implementation of this layer ([tss2-esys](https://github.com/tpm2-software/tpm2-tss/tree/master/src/tss2-esys)).

  * The [System API (SAPI)](https://trustedcomputinggroup.org/resource/tss-system-level-api-and-tpm-command-transmission-interface-specification/)
  provides the developer functionality that maps to the TPM 2.0 commands.
  The Kmyth TPM 2.0 code is currently based primarily on this layer
  ([tss2-sys](https://github.com/tpm2-software/tpm2-tss/tree/master/src/tss2-sys))
  of the TSS2 library.

  * The [TPM Command Transmission Interface (TCTI)](https://trustedcomputinggroup.org/resource/tss-system-level-api-and-tpm-command-transmission-interface-specification/)
  represents the layer where the actual TPM commands and responses are
  exchanged. In the TSS2 library, this layer is implemented by the
  [tss2-tcti](https://github.com/tpm2-software/tpm2-tss/tree/master/src/tss2-tcti)
  component.

  * [TSS 2.0 Marshalling/Unmarshalling](https://trustedcomputinggroup.org/resource/tcg-tss-2-0-marshalingunmarshaling-api-specification/)
  functionality is used to convert back and forth between C structures in the
  SAPI layer and the canonicalized commands/responses found in the TCTI layer.
  In the TSS2 library, these features are implemented by the
  [tss2-mu](https://github.com/tpm2-software/tpm2-tss/tree/master/src/tss2-mu)
  component.

  * The [TPM Access Broker (TAB)](https://trustedcomputinggroup.org/resource/tss-tab-and-resource-manager/)
  layer controls multi-process synchronization for the TPM. The
  [Resource Manager (RM)](https://trustedcomputinggroup.org/resource/tss-tab-and-resource-manager/)
  swaps TPM sessions and objects in and out of very limited TPM memory, as
  needed. An open source implementation of these two layers is provided by the
  [TPM2 Access Broker & Resource Manager Daemon (tss2-abrmd)](https://github.com/tpm2-software/tpm2-abrmd).

  * At the bottom of the software stack, the
  [TPM device driver](https://trustedcomputinggroup.org/resource/tcg-pc-client-device-driver-design-principles-for-tpm-2-0/)
  handles the physical transmission of data to and from the TPM. This is
  totally abstracted from our Kmyth code, however.

### TPM 2.0 emulator

* [IBM's TPM 2.0 emulator](https://sourceforge.net/projects/ibmswtpm2/)
defaults to using:

  * hostname : 127.0.0.1 (or local host) 

  * port : 2321 (tpm command) and 2322 (platform)

* Microsoft provides
  [the official TCG reference implementation of the TPM 2.0 Specification](https://github.com/microsoft/ms-tpm-20-ref).
  The project includes Windows (Visual Studio) and Linux (autotools) build
  scripts. Kmyth has not yet been tested using this TPM 2.0 simulator (mssim).

### TPM 2.0 Tools (Intel) 

* the *tpm2-abrmd* binary is used to start the TPM Access Broker (TAB) and
Resource Manager (RM) daemon.

* The *tpm2_takeownership* binary can be used to set (change) the TPM's owner
(storage) and endorsement hierarchy passwords (empty string by default),
as well as the lockout authorization value.

### TPM 2.0 Resource Manager (Intel)

* Can be run on either emulator or device. 

* Must be run in root if running on device.

* Must be in white list group or root to run. 

* To white list a group do the following:

  * In /etc/dbus-1/system.d/tpm2-abrmd.conf add:
  ```
        <policy group="[insert name of group here]">
        <allow own="com.intel.tss2.Tabrmd">
        </policy>
  ```

  * Then reset connection (e.g., dzdo pkill -HUP dbus-daemon)

* Valgrind gives glib errors when connecting to resource manager. These are
known errors present in the glib code. To supress only these errors do
the following: 

  * Create a file, say libgio.supp, with the following text:
  ```
        {
          ignore_libglib_stuff
          Memcheck:Leak
          ...
          obj:*/libglib-2.0.so.*
        }
        {
          ignore_lib_gobject_stuff
          Memcheck:Leak
          ...
          obj:*/libgobject-2.0.so.*
        }
  ```

  * Then run valgrind with option --suppressions=libgio.supp

### TPM_SU options:

#### TPM_SU_CLEAR:

* On TPM2_Shutdown() it indicates that the TPM should prepare for loss of
  power and save state required for an orderly startup TPM Reset.

* On TPM2_Startup() it indicates that the TPM should perform Reset or
  Restart.

#### TPM_SU_STATE:

* On TPM2_Shutdown(), it indicates that the TPM should prepare for loss of
power and save state required for an orderly startup (TPM Restart or
Resume).

* On TPM2_Startup(), it indicates that the TPM should restore the state
saved by the last TPM2_Shutdown().

### TPM 2.0 Key Handles:

* 0x80XXXXXX - Transient Objects that will not stay loaded between boots.

* 0x81XXXXXX - Persistent Objects that should stay loaded if you reboot.
the machine.

### TPM 2.0 Keys:

* A key hierarchy is created in TPM 2.0 by deriving a primary key using the
TPM2_CreatePrimary() command.

  * A primary key has a "type" (e.g., must use one of the algorithms
  supported by the TPM.

  * The unique parameter in the inPublic struct passed to
  TPM2_CreatePrimary() provides a mechanism for the caller to
  generate (derive) different primary keys for the same algorithm
  within the same TPM hierarchy.

  * The outsideInfo parameter passed to TPM2_CreatePrimary() is
  a label for the primary key's creationData.

  * "TPM2.0 in Context" (Proudler, Chen, and Dalton) quote:

>> "Other input fields in TPM2_CreatePrimary are there to enable
>>  production of a 'creation' credential that is returned by the
>>  TPM2 with the SRK. The creation credential describes the
>>  circumstances in which the SRK was created: the current values
>>  of the selected PCRs ("creationPCR"), the name of the parent key
>>  (the reserved handle of the SPS), plus an arbitrary label
>>  ("outsideInfo") describing the SRK. Just like the SRK itself,
>>  this credential can be recreated at any time by repeating the
>>  TPM2_CreatePrimary command with the same parameters, as long
>>  as the SPS hasn't changed."

* A key hierarchy is populated (e.g., Kmyth creates storage keys and
sealed data objects) by using the TPM2_Create() command. Non-primary
key and data objects have the following objectAttributes:

 * fixedTPM: SET prevents the key from being duplicated

 * stClear: SET clears object if platform properly switched off

 * fixedParent:  SET only allows duplication with the parent
 (parent must also be duplicable).

 * sensitiveDataOrigin:  SET indicates privKey generated by TPM

 * userWithAuth:  CLEAR forces policy authorization for USER role

 * adminWithPolicy:  SET forces policy authorization for ADMIN role

 * noDA:  CLEAR enables dictionary attack protections

 * encryptedDuplication:  SET forces encryption of sensitive portion
 of an object when duplicated.

 * restricted:  SET means that key will refuse to operate on external
 data that mimics TPM-generated data. Storage keys (keys that are
 parents of other keys) must be restricted.

 * decrypt: SET means key can be used for decryption

 * sign:  SET means key can be used for signatures

---

## Security Guidance

### Random-Sources

The most reliable and available source of random on a commercial machine is
the kernel entropy accumulator. On modern UNIX/Linux machine this takes the
form of /dev/random and /dev/urandom. These random sources have the advantage
of being able to collect entropy from a variety of sources only available to
the kernel. If correctly configured, they can carry entropy across a reboot
cycle.

We use OpenSSL's RAND_bytes to generate our wrapping key. It seeds from
/dev/urandom.

The user should be aware of the slow start issue present in kernel entropy
accumulators. When a random number generator (RNG) is first configured, it
has very little information available which cannot be guessed. Various
mitigations for this problem are available, among them, writing a fresh random
seed from some known good source to the entropy accumulator by writing to
/dev/random. As the RNG continues to run, and more system input is fed in
(interrupt timings, packet data, keyboard activity,...), anyone who is not in
a position to see all of the input will eventually lose track of the internal
state of the RNG.

### Local Storage of Sensitive Material

For some applications, sensitive material must be available through the
operating system's file IO interface; for example, one may need operational
key accesible to processes that expect to read key material from a file. One
option for limiting the exposure of sensitive material is to store it in a
file in the ramfs RAM file system. We do not recommend the tmpfs RAM file
system, because tmpfs may use swap space.


