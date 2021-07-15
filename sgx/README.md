The code maintained here provides ECALLs and OCALLs for SGX enclaves
that need to seal or unseal data into the enclave. In order to use it
you must create your own enclave, include ```kmyth_enclave.edl``` in
your ```.edl``` file, and build the ECALL and OCALL object files as
part of your application and enclave.

