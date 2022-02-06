# Kmyth SGX Integration

The code maintained here provides functionality supporting kmyth
features implemented within SGX enclaves. This includes the ECALLs and
OCALLs needed to seal or unseal data into the enclave. In order to use
it you must create your own enclave, include ```kmyth_enclave.edl```
in your ```.edl``` file, and build the object files for this
functionality as part of your application and enclave. The ```demo```
directory contains an example application that performs an ECDH key
agreement with a "remote" server and securely retrieves a key from the
remote server into the enclave. For more information on the demo see
[Tests and Demo](TESTING.md).

Some key features of the provided demonstration files worth noting include:
* The ```kmyth_enclave.edl``` file is included in
  ```kmyth_sgx_retreive_key_demo_enclave.edl```.
* The name of the SGX EDGER8R generated header files are specified
  in the ```Makefile```:
```
ENCLAVE_HEADER_TRUSTED ?= '"Name of the header for the trusted portion"'
ENCLAVE_HEADER_UNTRUSTED ?= '"Name of the header for the untrusted portion"'
```
* The locations of the SGX SSL libraries are specified in the ```Makefile```:
```
SGX_SSL_UNTRUSTED_LIB_PATH ?= <path to SGX SSL untrusted libraries>
SGX_SSL_TRUSTED_LIB_PATH ?= <path to SGX SSL trusted libraries>
SGX_SSL_INCLUDE_PATH ?= <path to SGX SSL headers>
```
* The ```App_Link_Flags``` includes both ```-L$(SGX_SSL_UNTRUSTED_LIB_PATH)```
  and ```-lsgx_usgxssl```.
* The ```Enclave_Include_Paths``` includes ```-I$(SGX_SSL_INCLUDE_PATH)```.
* The ```Enclave_C_Flags``` includes
  ```-DENCLAVE_HEADER_TRUSTED=$(ENCLAVE_HEADER_TRUSTED)```
* The ```App_C_Flags``` includes
  ```-DENCLAVE_HEADER_UNTRUSTED=$(ENCLAVE_HEADER_UNTRUSTED)```
* The ```Enclave_Cpp_Flags``` includes ```--include "tsgxsslio.h"
* The ```Enclave_Link_Flags``` includes
```
-L$(SGX_SSL_TRUSTED_LIB_PATH) \
-Wl,--whole-archive -lsgx_tsgxssl \
-Wl,--no-whole-archive -lsgx_tsgxssl_crypto \
```
* The location of the ```kmyth_enclave.edl``` file is included in the search
  path for ```SGX_EDGER8R``` along with ```$(SGX_SSL_INCLUDE_PATH)```
```
Enclave_Name = kmyth_sgx_retrieve_key_demo_enclave
```
```
enclave/$(Enclave_Name)_t.c: $(SGX_EDGER8R) enclave/$(Enclave_Name).edl
	@cd enclave && $(SGX_EDGER8R) --trusted $(Enclave_Name).edl \
                                --search-path $(SGX_SDK)/include \
                                --search-path . \
                                --search-path ../../trusted \
                                --search-path $(SGX_SSL_INCLUDE_PATH)
	@echo "GEN  =>  $@"
```
```
enclave/$(Enclave_Name)_u.c: $(SGX_EDGER8R) enclave/$(Enclave_Name).edl
	@cd enclave && $(SGX_EDGER8R) --untrusted $(Enclave_Name).edl \
                                --search-path $(SGX_SDK)/include \
                                --search-path . \
                                --search-path ../../trusted \
                                --search-path $(SGX_SSL_INCLUDE_PATH)
	@echo "GEN  =>  $@"
```
* The common (functions callable from either trusted or untrusted space)
  portion of the kmyth enclave is built as part of building the
  Common Objects in the ```Makefile```:
```
enclave/ec_key_cert_marshal.o: ../common/src/ec_key_cert_marshal.c
  @$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

enclave/ec_key_cert_unmarshal.o: ../common/src/ec_key_cert_unmarshal.c
  @$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"
```
* The trusted portion of the kmyth enclave is built as part of building the
  Enclave Objects in the ```Makefile```:
```
enclave/kmyth_enclave_memory_util.o: ../trusted/src/util/kmyth_enclave_memory_util.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

enclave/kmyth_enclave_seal.o: ../trusted/src/ecall/kmyth_enclave_seal.cpp
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

enclave/kmyth_enclave_unseal.o: ../trusted/src/ecall/kmyth_enclave_unseal.cpp
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

enclave/kmyth_enclave_retrieve_key.o: ../trusted/src/ecall/kmyth_enclave_retrieve_key.cpp
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

```
* Your ```$(Enclave_Link_Flags)``` must contain ```-lsgx_tstdc``` to link against the thread synchronization primitives.

* The kmyth enclave object files are linked against enclave:

```
Enclave_Lib = kmyth_sgx_retrieve_key_demo_enclave.so
```
```
enclave/$(Enclave_Lib): enclave/$(Enclave_Name)_t.o \
                        enclave/kmyth_enclave_memory_util.o \
                        enclave/ec_key_cert_unmarshal.o \
                        enclave/kmyth_enclave_seal.o \
                        enclave/kmyth_enclave_unseal.o \
                        enclave/kmyth_enclave_retrieve_key.o
	@$(CXX) $^ -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"
```
