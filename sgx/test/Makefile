#
# Copyright (C) 2011-2016 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#

######## SGX SDK Build Settings ########

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= SIM
SGX_ARCH ?= x64
SGX_SSL_UNTRUSTED_LIB_PATH ?= /opt/intel/sgxssl/lib64/
SGX_SSL_TRUSTED_LIB_PATH ?= /opt/intel/sgxssl/lib64/
SGX_SSL_INCLUDE_PATH ?= /opt/intel/sgxssl/include/

ENCLAVE_HEADER_TRUSTED ?= '"kmyth_sgx_test_enclave_t.h"'
ENCLAVE_HEADER_UNTRUSTED ?= '"kmyth_sgx_test_enclave_u.h"'

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
	SGX_COMMON_CFLAGS += -O0 -g
else
	SGX_COMMON_CFLAGS += -O2
endif

######## App (untrusted code) Build Settings ########

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

App_Name := bin/kmyth_enclave_tests

App_Source_Files := app/kmyth_sgx_test.c \
                    ../untrusted/src/wrapper/sgx_seal_unseal_impl.c

App_Include_Paths := -Ienclave
App_Include_Paths += -I../untrusted/include/ocall
App_Include_Paths += -I../untrusted/include/util
App_Include_Paths += -I../untrusted/include/wrapper
App_Include_Paths += -I../common/include
App_Include_Paths += -I$(SGX_SDK)/include
App_Include_paths += -I../../utils/include
App_Include_Paths += -I../../logger/include
App_Include_Paths += -I../../include/network

App_C_Flags := $(SGX_COMMON_CFLAGS)
App_C_Flags += -fPIC
App_C_Flags += -Wno-attributes
App_C_Flags += $(App_Include_Paths)
App_C_Flags += -DENCLAVE_HEADER_UNTRUSTED=$(ENCLAVE_HEADER_UNTRUSTED)

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
	App_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	App_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
	App_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

App_Cpp_Flags := $(App_C_Flags) -std=c++11

App_Link_Flags := $(SGX_COMMON_CFLAGS)
App_Link_Flags += -L$(SGX_LIBRARY_PATH)
App_Link_Flags += -L$(SGX_SSL_UNTRUSTED_LIB_PATH)
App_Link_Flags += -Lenclave
App_Link_Flags += -L../../lib
App_Link_Flags += -l$(Urts_Library_Name)
App_Link_Flags += -lcunit
App_Link_Flags += -lpthread
App_Link_Flags += -lsgx_usgxssl
App_Link_Flags += -Wl,-rpath=../../lib -lkmyth-utils -lkmyth-logger -lkmyth-tpm

ifneq ($(SGX_MODE), HW)
	App_Link_Flags += -lsgx_uae_service_sim
else
	App_Link_Flags += -lsgx_uae_service
endif

######## Enclave Build Settings ########

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif
Crypto_Library_Name := sgx_tcrypto

Enclave_Include_Paths := -Ienclave
Enclave_Include_Paths += -I../trusted/include
Enclave_Include_Paths += -I../trusted/include/util
Enclave_Include_Paths += -I../trusted/include/wrapper
Enclave_Include_Paths += -I../common/include
Enclave_Include_Paths += -I$(SGX_SDK)/include
Enclave_Include_Paths += -I$(SGX_SDK)/include/tlibc
Enclave_Include_Paths += -I$(SGX_SDK)/include/stlport
Enclave_Include_Paths += -I$(SGX_SSL_INCLUDE_PATH)
Enclave_Include_Paths += -I/usr/local/include
Enclave_Include_Paths += -I../../include
Enclave_Include_Paths += -I../../include/cipher
Enclave_Include_Paths += -I../../include/protocol
Enclave_Include_Paths += -I../../utils/include/kmyth

Enclave_C_Flags := -Wall
Enclave_C_Flags += $(SGX_COMMON_CFLAGS)
Enclave_C_Flags += -nostdinc
Enclave_C_Flags += -fvisibility=hidden
Enclave_C_Flags += -fpie
Enclave_C_Flags += -fstack-protector
Enclave_C_Flags += $(Enclave_Include_Paths)
Enclave_C_Flags += -DENCLAVE_HEADER_TRUSTED=$(ENCLAVE_HEADER_TRUSTED)
Enclave_C_Flags += -DKMYTH_SGX

Enclave_Cpp_Flags := $(Enclave_C_Flags)
Enclave_Cpp_Flags += -std=c++03
Enclave_Cpp_Flags += -nostdinc++
Enclave_Cpp_Flags += --include "tsgxsslio.h"

Enclave_Link_Flags := $(SGX_COMMON_CFLAGS)
Enclave_Link_Flags += -Wl,--no-undefined
Enclave_Link_Flags += -nostdlib
Enclave_Link_Flags += -nodefaultlibs
Enclave_Link_Flags += -nostartfiles
Enclave_Link_Flags += -L$(SGX_SSL_TRUSTED_LIB_PATH)
Enclave_Link_Flags += -L$(SGX_LIBRARY_PATH)
Enclave_Link_Flags += -Wl,--whole-archive -lsgx_tsgxssl
Enclave_Link_Flags += -Wl,--no-whole-archive -lsgx_tsgxssl_crypto
Enclave_Link_Flags += -Wl,--whole-archive -l$(Trts_Library_Name)
Enclave_Link_Flags += -Wl,--no-whole-archive -Wl,--start-group
Enclave_Link_Flags +=   -lsgx_tstdc
Enclave_Link_Flags +=   -lsgx_tcxx
Enclave_Link_Flags +=   -lsgx_pthread
Enclave_Link_Flags +=   -l$(Crypto_Library_Name)
Enclave_Link_Flags +=   -l$(Service_Library_Name)
Enclave_Link_Flags += -Wl,--end-group
Enclave_Link_Flags += -Wl,-Bstatic
Enclave_Link_Flags += -Wl,-Bsymbolic
Enclave_Link_Flags += -Wl,-pie,-eenclave_entry
Enclave_Link_Flags += -Wl,--export-dynamic
Enclave_Link_Flags += -Wl,--defsym,__ImageBase=0
Enclave_Link_Flags += -lkmip-sgx

Enclave_Name := kmyth_sgx_test_enclave
Enclave_Lib := $(Enclave_Name).so
Enclave_Signing_Key := $(Enclave_Name)_private.pem
Signed_Enclave_Name := $(Enclave_Name).signed.so
Enclave_Config_File := $(Enclave_Name).config.xml

ifeq ($(SGX_MODE), HW)
ifneq ($(SGX_DEBUG), 1)
ifneq ($(SGX_PRERELEASE), 1)
Build_Mode = HW_RELEASE
endif
endif
endif

# Message for missing Enclave Signing Key - Fatal Build Error
define err_no_enclave_signing_key
FAIL - No Enclave Signing Key found
Generate or install enclave/$(Enclave_Signing_Key)
e.g., run 'openssl genrsa -out enclave/$(Enclave_Signing_Key) -3 3072'
endef

.PHONY: pre all run
pre:
	@mkdir -p bin 
	@if [ ! -f enclave/$(Enclave_Signing_Key) ]; then \
	   openssl genrsa -out enclave/$(Enclave_Signing_Key) -3 3072; \
	 fi
	@rm -f app/*~
	@rm -f ../untrusted/src/*/*~ ../untrusted/include/*/*~
	@rm -f ../trusted/src/*/*~ ../trusted/include/*~ ../trusted/include/*/*~
	@(test -f ../../lib/libkmyth-logger.so && \
		test -f ../../lib/libkmyth-utils.so) || make libs -C ../..

ifeq ($(Build_Mode), HW_RELEASE)
all: $(App_Name) $(Enclave_Lib)
	@echo "The project has been built in release hardware mode."
	@echo "Please sign the $(Enclave_Lib) first with your signing key before"
	@echo "you run the $(App_Name) to launch and access the enclave."
	@echo "To sign the enclave use the command:\n"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <your key>"
	@echo "                              -enclave $(Enclave_Lib)"
	@echo "                              -out <$(Signed_Enclave_Name)>"
	@echo "                              -config $(Enclave_Config_File)\n"
	@echo "You can also sign the enclave using an external signing tool."
	@echo "See User's Guide for more details."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build"
	@echo "the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."
else
all: pre $(App_Name) enclave/$(Signed_Enclave_Name)
endif

run: all
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/$(App_Name)
	@echo "RUN  =>  $(App_Name) [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif

######## Common Objects ########

enclave/ec_key_cert_marshal.o: ../common/src/ec_key_cert_marshal.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

enclave/ec_key_cert_unmarshal.o: ../common/src/ec_key_cert_unmarshal.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

enclave/ecdh_util.o: ../common/src/ecdh_util.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

######## App Objects ########

enclave/log_ocall.o: ../untrusted/src/ocall/log_ocall.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

enclave/memory_ocall.o: ../untrusted/src/ocall/memory_ocall.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

enclave/ecdh_ocall.o: ../untrusted/src/ocall/ecdh_ocall.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

enclave/$(Enclave_Name)_u.c: $(SGX_EDGER8R) enclave/$(Enclave_Name).edl
	@cd enclave && $(SGX_EDGER8R) --untrusted $(Enclave_Name).edl \
                                      --search-path $(SGX_SDK)/include \
                                      --search-path . \
                                      --search-path ../../trusted \
                                      --search-path $(SGX_SSL_INCLUDE_PATH)
	@echo "GEN  =>  $@"

enclave/$(Enclave_Name)_u.o: enclave/$(Enclave_Name)_u.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(App_Name): $(App_Source_Files) enclave/$(Enclave_Name)_u.o \
                                 enclave/ec_key_cert_marshal.o \
                                 enclave/ec_key_cert_unmarshal.o \
                                 enclave/ecdh_util.o \
                                 enclave/ecdh_ocall.o \
                                 enclave/memory_ocall.o \
                                 enclave/log_ocall.o
	@$(CXX) $^ -o $@ $(App_Cpp_Flags) $(App_Link_Flags) \
	                                  -Lenclave -lcrypto -lcunit
	@echo "LINK =>  $@"

######## Enclave Objects ########

enclave/$(Enclave_Name)_t.c: $(SGX_EDGER8R) enclave/$(Enclave_Name).edl
	@cd enclave && $(SGX_EDGER8R) --trusted $(Enclave_Name).edl \
		                      --search-path $(SGX_SDK)/include \
                                      --search-path . \
				      --search-path ../../trusted \
                                      --search-path $(SGX_SSL_INCLUDE_PATH)
	@echo "GEN  =>  $@"

enclave/$(Enclave_Name)_t.o: enclave/$(Enclave_Name)_t.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

enclave/kmyth_enclave_memory_util.o: \
		../trusted/src/util/kmyth_enclave_memory_util.c 
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

enclave/sgx_retrieve_key_impl.o: \
		../trusted/src/wrapper/sgx_retrieve_key_impl.c 
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

enclave/kmyth_sgx_test_trusted.o: enclave/kmyth_sgx_test_trusted.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

enclave/kmyth_enclave_seal.o: ../trusted/src/ecall/kmyth_enclave_seal.cpp 
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

enclave/kmyth_enclave_unseal.o: ../trusted/src/ecall/kmyth_enclave_unseal.cpp
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

enclave/kmyth_enclave_retrieve_key.o: \
		../trusted/src/ecall/kmyth_enclave_retrieve_key.cpp
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

enclave/aes_gcm.o: ../../src/cipher/aes_gcm.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

enclave/memory_util.o: ../../utils/src/memory_util.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

enclave/kmip_util.o: ../../src/protocol/kmip_util.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

enclave/$(Enclave_Lib): enclave/$(Enclave_Name)_t.o \
                        enclave/kmyth_sgx_test_trusted.o \
                        enclave/ec_key_cert_marshal.o \
                        enclave/ec_key_cert_unmarshal.o \
                        enclave/ecdh_util.o \
                        enclave/kmyth_enclave_memory_util.o \
                        enclave/sgx_retrieve_key_impl.o \
                        enclave/kmyth_enclave_seal.o \
                        enclave/kmyth_enclave_unseal.o \
                        enclave/kmyth_enclave_retrieve_key.o \
                        enclave/aes_gcm.o \
                        enclave/memory_util.o \
                        enclave/kmip_util.o
	@$(CXX) $^ -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

enclave/$(Enclave_Signing_Key):
	$(error $(err_no_enclave_signing_key))

enclave/$(Signed_Enclave_Name): enclave/$(Enclave_Lib) \
                                enclave/$(Enclave_Signing_Key)
	@$(SGX_ENCLAVE_SIGNER) sign -key enclave/$(Enclave_Signing_Key) \
		                    -enclave enclave/$(Enclave_Lib) \
		                    -out $@ \
	                            -config enclave/$(Enclave_Config_File)
	@echo "SIGN =>  $@"

.PHONY: test

test: all
	./bin/kmyth_enclave_tests 2> /dev/null

.PHONY: clean

clean:
	@rm -f enclave/*_t.h enclave/*_u.h enclave/*_t.c enclave/*_u.c
	@rm -f enclave/*.o enclave/*.so enclave/*.pem
	@rm -rf bin
