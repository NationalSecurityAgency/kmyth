The code maintained here provides ECALLs and OCALLs for SGX enclaves
that need to seal or unseal data into the enclave. In order to use it
you must create your own enclave, include ```kmyth_enclave.edl``` in
your ```.edl``` file, and build the ECALL and OCALL object files as
part of your application and enclave. The ```tests``` directory
contains a simple example.

The key features you should note in the test files are:
* The ```kmyth_enclave.edl``` file is included in ```kmyth_sgx_test_enclave.edl```.
* The name of the SGX EDGER8R generated header files are specified given in the ```Makefile```:
```
ENCLAVE_HEADER_TRUSTED ?= '"Name of the header for the trusted portion"'
ENCLAVE_HEADER_UNTRUSTED ?= '"Name of the header for the untrusted portion"'
```
* The locations of the SGX SSL libraries are given in the ```Makefile```:
```
SGX_SSL_UNTRUSTED_LIB_PATH ?= <path to SGX SSL untrusted libraries>
SGX_SSL_TRUSTED_LIB_PATH ?= <path to SGX SSL trusted libraries>
SGX_SSL_INCLUDE_PATH ?= <path to SGX SSL headers>
```
* The ```App_Link_Flags``` includes both ```-L$(SGX_SSL_UNTRUSTED_LIB_PATH)``` and ```-lsgx_usgxssl```.
* The ```Enclave_Include_Paths``` includes ```-I$(SGX_SSL_INCLUDE_PATH)```.
* The ```Enclave_C_Flags``` includes ```-DENCLAVE_HEADER_TRUSTED=$(ENCLAVE_HEADER_TRUSTED)```
* The ```App_C_Flags``` includes ```-DENCLAVE_HEADER_UNTRUSTED=$(ENCLAVE_HEADER_UNTRUSTED)```
* The ```Enclave_Cpp_Flags``` includes ```--include "tsgxsslio.h"
* The ```Enclave_Link_Flags``` includes
```
-L$(SGX_SSL_TRUSTED_LIB_PATH) \
-Wl,--whole-archive -lsgx_tsgxssl \
-Wl,--no-whole-archive -lsgx_tsgxssl_crypto \
```
* The location of the ```kmyth_enclave.edl``` file is included in the search path for ```SGX_EDGER8R``` along with ```$(SGX_SSL_INCLUDE_PATH)```
```
enclave/kmyth_sgx_test_enclave_t.c: $(SGX_EDGER8R) enclave/kmyth_sgx_test_enclave.edl
	@cd enclave && $(SGX_EDGER8R) --trusted kmyth_sgx_test_enclave.edl --search-path $(SGX_SDK)/include --search-path . --search-path ../../trusted/kmyth_enclave --search-path $(SGX_SSL_INCLUDE_PATH)
	@echo "GEN  =>  $@"
```
```
enclave/kmyth_sgx_test_enclave_u.c: $(SGX_EDGER8R) enclave/kmyth_sgx_test_enclave.edl
	@cd enclave && $(SGX_EDGER8R) --untrusted kmyth_sgx_test_enclave.edl --search-path $(SGX_SDK)/include --search-path . --search-path ../../trusted/kmyth_enclave --search-path $(SGX_SSL_INCLUDE_PATH)
	@echo "GEN  =>  $@"
```
* The trusted portion of the kmyth enclave is built as part of building the Enclave Objects in the ```Makefile```:
```
enclave/kmyth_enclave_seal.o: ../trusted/src/kmyth_enclave_seal.cpp
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

enclave/kmyth_enclave_unseal.o: ../trusted/src/kmyth_enclave_unseal.cpp
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"
```
* Your ```$(Enclave_Link_Flags)``` must contain ```-lsgx_tstdc``` to link against the thread synchronization primitives.

* The kmyth enclave ecalls object file is linked against enclave:
```
enclave/$(Enclave_Name): enclave/kmyth_sgx_test_enclave_t.o enclave/kmyth_enclave_seal.o enclave/kmyth_enclave_unseal.o
	@$(CXX) $^ -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"
```
