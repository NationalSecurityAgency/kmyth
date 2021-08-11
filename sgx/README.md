The code maintained here provides ECALLs and OCALLs for SGX enclaves
that need to seal or unseal data into the enclave. In order to use it
you must create your own enclave, include ```kmyth_enclave.edl``` in
your ```.edl``` file, and build the ECALL and OCALL object files as
part of your application and enclave. The ```tests``` directory
contains a simple example.

The key features you should note in the test files are:
* The ```kmyth_enclave.edl``` file is included in ```kmyth_sgx_test_enclave.edl```.
* The location of the ```kmyth_enclave.edl``` file is included in the search path for ```SGX_EDGER8R```:
```
sgx/kmyth_sgx_test_enclave_t.c: $(SGX_EDGER8R) sgx/kmyth_sgx_test_enclave.edl
	@cd sgx && $(SGX_EDGER8R) --trusted kmyth_sgx_test_enclave.edl --search-path $(SGX_SDK)/include --search-path . --search-path ../../../sgx/kmyth_enclave
	@echo "GEN  =>  $@"
```
```
sgx/kmyth_sgx_test_enclave_u.c: $(SGX_EDGER8R) sgx/kmyth_sgx_test_enclave.edl
	@cd sgx && $(SGX_EDGER8R) --untrusted kmyth_sgx_test_enclave.edl --search-path $(SGX_SDK)/include --search-path . --search-path ../../../sgx/kmyth_enclave
	@echo "GEN  =>  $@"
```
* The trusted portion of the kmyth enclave is built as part of building the Enclave Objects in the ```Makefile```:
```
sgx/kmyth_enclave_trusted.o: ../../sgx/kmyth_enclave/kmyth_enclave_trusted.cpp
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"
```
* The kmyth enclave ecalls object file is linked against enclave:
```
sgx/$(Enclave_Name): sgx/kmyth_sgx_test_enclave_t.o sgx/kmyth_enclave_trusted.o
	@$(CXX) $^ -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"
```
* In the future the kmyth enclave may also provide ocalls, in which case they would have to be built and linked against the untrusted application, not the enclave.
