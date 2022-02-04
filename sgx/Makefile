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

TEST_ENCLAVE_HEADER_TRUSTED ?= '"kmyth_sgx_test_enclave_t.h"'
TEST_ENCLAVE_HEADER_UNTRUSTED ?= '"kmyth_sgx_test_enclave_u.h"'

DEMO_ENCLAVE_HEADER_TRUSTED ?= '"kmyth_sgx_retrieve_key_demo_enclave_t.h"'
DEMO_ENCLAVE_HEADER_UNTRUSTED ?= '"kmyth_sgx_retrieve_key_demo_enclave_u.h"'

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

Test_App_Name := test/bin/kmyth_enclave_tests
Demo_App_Name := demo/bin/kmyth_sgx_retrieve_key_demo

Test_App_Source_Files := test/app/kmyth_sgx_test.c \
	                 untrusted/src/wrapper/sgx_seal_unseal_impl.c

Demo_App_Source_files := demo/app/kmyth_sgx_retrieve_key_demo.c


Common_App_Include_Paths := -Iuntrusted/include/ocall
Common_App_Include_Paths += -Iuntrusted/include/util
Common_App_Include_Paths += -Iuntrusted/include/wrapper
Common_App_Include_Paths += -Icommon/include
Common_App_Include_Paths += -I$(SGX_SDK)/include
Common_App_Include_Paths += -I../include/network

Test_App_Include_Paths := -Itest/enclave
Test_App_Include_Paths += -I../utils/include
Test_App_Include_Paths += -I../logger/include
Test_App_Include_Paths += $(Common_App_Include_Paths)

#Demo_App_Include_Paths := -Idemo/include
Demo_App_Include_Paths += -Idemo/enclave
Demo_App_Include_Paths += -Idemo/server/include
Demo_App_Include_Paths += -I../include/protocol
Demo_App_Include_Paths += $(Common_App_Include_Paths)

Common_App_C_Flags := $(SGX_COMMON_CFLAGS)
Common_App_C_Flags += -fPIC
Common_App_C_Flags += -Wno-attributes

Test_App_C_Flags := $(Test_App_Include_Paths)
Test_App_C_Flags += -DENCLAVE_HEADER_UNTRUSTED=$(TEST_ENCLAVE_HEADER_UNTRUSTED)

Demo_App_C_Flags := $(Demo_App_Include_Paths)
Demo_App_C_Flags += -DENCLAVE_HEADER_UNTRUSTED=$(DEMO_ENCLAVE_HEADER_UNTRUSTED)

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
	Common_App_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Common_App_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
	Common_App_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

Test_App_C_Flags += $(Common_App_C_Flags)
Demo_App_C_Flags += $(Common_App_C_Flags)

Test_App_Cpp_Flags := $(Test_App_C_Flags) -std=c++11
Demo_App_Cpp_Flags := $(Demo_App_C_Flags) -std=c++11

Common_App_Link_Flags := $(SGX_COMMON_CFLAGS)
Common_App_Link_Flags += -L$(SGX_LIBRARY_PATH)
Common_App_Link_Flags += -L$(SGX_SSL_UNTRUSTED_LIB_PATH)
Common_App_Link_Flags += -l$(Urts_Library_Name)
Common_App_Link_Flags += -lsgx_usgxssl
Common_App_Link_Flags += -lpthread
Common_App_Link_Flags += -lkmyth-utils
Common_App_Link_Flags += -lkmyth-logger
Common_App_Link_Flags += -lkmyth-tpm

ifneq ($(SGX_MODE), HW)
	Common_App_Link_Flags += -lsgx_uae_service_sim
else
	Common_App_Link_Flags += -lsgx_uae_service
endif

Test_App_Link_Flags := $(Common_App_Link_Flags)
Test_App_Link_Flags += -Ltest/enclave
Test_App_Link_Flags += -L../lib
Test_App_Link_Flags += -lcunit
Test_App_Link_Flags += -Wl,-rpath=../lib

Demo_App_Link_Flags := $(Common_App_Link_Flags)
Demo_App_Link_Flags += -Ldemo/enclave
Demo_App_Link_Flags += -lcrypto


######## Enclave Build Settings ########

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif
Crypto_Library_Name := sgx_tcrypto

Common_Enclave_Include_Paths := -Itrusted/include
Common_Enclave_Include_Paths += -Itrusted/include/util
Common_Enclave_Include_Paths += -Itrusted/include/wrapper
Common_Enclave_Include_Paths += -Icommon/include
Common_Enclave_Include_Paths += -I$(SGX_SDK)/include
Common_Enclave_Include_Paths += -I$(SGX_SDK)/include/tlibc
Common_Enclave_Include_Paths += -I$(SGX_SDK)/include/stlport
Common_Enclave_Include_Paths += -I$(SGX_SSL_INCLUDE_PATH)
Common_Enclave_Include_Paths += -I/usr/local/include
Common_Enclave_Include_Paths += -I../include
Common_Enclave_Include_Paths += -I../include/cipher
Common_Enclave_Include_Paths += -I../include/protocol
Common_Enclave_Include_Paths += -I../utils/include/kmyth

Test_Enclave_Include_Paths := $(Common_Enclave_Include_Paths)
Test_Enclave_Include_Paths += -Itest/enclave

Demo_Enclave_Include_Paths := $(Common_Enclave_Include_Paths)
Demo_Enclave_Include_Paths += -Idemo/enclave

Common_Enclave_C_Flags := -Wall
Common_Enclave_C_Flags += $(SGX_COMMON_CFLAGS)
Common_Enclave_C_Flags += -nostdinc
Common_Enclave_C_Flags += -fvisibility=hidden
Common_Enclave_C_Flags += -fpie
Common_Enclave_C_Flags += -fstack-protector
Common_Enclave_C_Flags += -DKMYTH_SGX

Test_Enclave_C_Flags := $(Common_Enclave_C_Flags)
Test_Enclave_C_Flags += $(Test_Enclave_Include_Paths)
Test_Enclave_C_Flags += -DENCLAVE_HEADER_TRUSTED=$(TEST_ENCLAVE_HEADER_TRUSTED)

Demo_Enclave_C_Flags := $(Common_Enclave_C_Flags)
Demo_Enclave_C_Flags += $(Demo_Enclave_Include_Paths)
Demo_Enclave_C_Flags += -DENCLAVE_HEADER_TRUSTED=$(DEMO_ENCLAVE_HEADER_TRUSTED)

Common_Enclave_Cpp_Flags := -std=c++03
Common_Enclave_Cpp_Flags += -nostdinc++
Common_Enclave_Cpp_Flags += --include "tsgxsslio.h"

Test_Enclave_Cpp_Flags := $(Test_Enclave_C_Flags)
Test_Enclave_Cpp_Flags += $(Common_Enclave_Cpp_Flags)

Demo_Enclave_Cpp_Flags := $(Demo_Enclave_C_Flags)
Demo_Enclave_Cpp_Flags += $(Common_Enclave_Cpp_Flags)

Common_Enclave_Link_Flags := $(SGX_COMMON_CFLAGS)
Common_Enclave_Link_Flags += -Wl,--no-undefined
Common_Enclave_Link_Flags += -nostdlib
Common_Enclave_Link_Flags += -nodefaultlibs
Common_Enclave_Link_Flags += -nostartfiles
Common_Enclave_Link_Flags += -L$(SGX_SSL_TRUSTED_LIB_PATH)
Common_Enclave_Link_Flags += -L$(SGX_LIBRARY_PATH)
Common_Enclave_Link_Flags += -Wl,--whole-archive -lsgx_tsgxssl
Common_Enclave_Link_Flags += -Wl,--no-whole-archive -lsgx_tsgxssl_crypto
Common_Enclave_Link_Flags += -Wl,--whole-archive -l$(Trts_Library_Name)
Common_Enclave_Link_Flags += -Wl,--no-whole-archive -Wl,--start-group
Common_Enclave_Link_Flags +=   -lsgx_tstdc
Common_Enclave_Link_Flags +=   -lsgx_tcxx
Common_Enclave_Link_Flags +=   -lsgx_pthread
Common_Enclave_Link_Flags +=   -l$(Crypto_Library_Name)
Common_Enclave_Link_Flags +=   -l$(Service_Library_Name)
Common_Enclave_Link_Flags += -Wl,--end-group
Common_Enclave_Link_Flags += -Wl,-Bstatic
Common_Enclave_Link_Flags += -Wl,-Bsymbolic
Common_Enclave_Link_Flags += -Wl,-pie,-eenclave_entry
Common_Enclave_Link_Flags += -Wl,--export-dynamic
Common_Enclave_Link_Flags += -Wl,--defsym,__ImageBase=0
Common_Enclave_Link_Flags += -lkmip-sgx

Test_Enclave_Link_Flags := $(Common_Enclave_Link_Flags)

Demo_Enclave_Link_Flags := $(Common_Enclave_Link_Flags)
Demo_Enclave_Link_Flags += -L/usr/local/lib

Test_Enclave_Name := kmyth_sgx_test_enclave
Test_Enclave_Lib := $(Test_Enclave_Name).so
Test_Enclave_Signing_Key := $(Test_Enclave_Name)_private.pem
Test_Signed_Enclave_Name := $(Test_Enclave_Name).signed.so
Test_Enclave_Config_File := $(Test_Enclave_Name).config.xml

Demo_Enclave_Name := kmyth_sgx_retrieve_key_demo_enclave
Demo_Enclave_Lib := $(Demo_Enclave_Name).so
Demo_Enclave_Signing_Key := $(Demo_Enclave_Name)_private.pem
Demo_Signed_Enclave_Name := $(Demo_Enclave_Name).signed.so
Demo_Enclave_Config_File := $(Demo_Enclave_Name).config.xml

ifeq ($(SGX_MODE), HW)
ifneq ($(SGX_DEBUG), 1)
ifneq ($(SGX_PRERELEASE), 1)
Build_Mode = HW_RELEASE
endif
endif
endif

######## Demo Server Build Settings ########

Server_Name := demo/bin/ecdh-server
Client_Name := demo/bin/ecdh-client

# Message for missing Demo Enclave Signing Key - Fatal Build Error
define err_no_demo_enclave_signing_key
FAIL - No Demo Enclave Signing Key found
Generate or install demo/enclave/$(DemoEnclave_Signing_Key)
e.g., run 'openssl genrsa -out demo/enclave/$(Demo_Enclave_Signing_Key) -3 3072'
endef

# Message for missing Test Enclave Signing Key - Fatal Build Error
define err_no_test_enclave_signing_key
FAIL - No Test Enclave Signing Key found
Generate or install test/enclave/$(Test_Enclave_Signing_Key)
e.g., run 'openssl genrsa -out test/enclave/$(Test_Enclave_Signing_Key) -3 3072'
endef

.PHONY: test-pre test-all test-run demo-pre demo-all demo-test-keys-certs demo
test-pre:
	@mkdir -p test/bin 
	@if [ ! -f test/enclave/$(Test_Enclave_Signing_Key) ]; then \
	   openssl genrsa -out test/enclave/$(Test_Enclave_Signing_Key) -3 3072; \
	 fi
	@rm -f test/app/*~
	@rm -f untrusted/src/*/*~ untrusted/include/*/*~
	@rm -f trusted/src/*/*~ trusted/include/*~ trusted/include/*/*~
	@(test -f ../lib/libkmyth-logger.so && \
		test -f ../lib/libkmyth-utils.so) || make libs -C ../

demo-pre:
	@mkdir -p demo/bin 
	@if [ ! -f demo/enclave/$(Demo_Enclave_Signing_Key) ]; then \
	   openssl genrsa -out demo/enclave/$(Demo_Enclave_Signing_Key) -3 3072; \
	 fi
	@rm -f demo/app/*~
	@rm -f untrusted/src/*/*~ untrusted/include/*/*~
	@rm -f trusted/src/*/*~ trusted/include/*~ trusted/include/*/*~

ifeq ($(Build_Mode), HW_RELEASE)
test-all: $(Test_App_Name) $(Test_Enclave_Lib)
	@echo "The project has been built in release hardware mode."
	@echo "Please sign the $(Test_Enclave_Lib) first with your signing key before"
	@echo "you run the $(Test_App_Name) to launch and access the enclave."
	@echo "To sign the enclave use the command:\n"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <your key>"
	@echo "                              -enclave $(Test_Enclave_Lib)"
	@echo "                              -out <$(Test_Signed_Enclave_Name)>"
	@echo "                              -config $(Test_Enclave_Config_File)\n"
	@echo "You can also sign the enclave using an external signing tool."
	@echo "See User's Guide for more details."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build"
	@echo "the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."
else
test-all: test-pre $(Test_App_Name) test/enclave/$(Test_Signed_Enclave_Name)
endif

ifeq ($(Build_Mode), HW_RELEASE)
demo-all: demo-pre $(Demo_Enclave_Lib) $(Demo_App_Name) $(Server_Name) $(Client_Name)
	@echo "The project has been built in release hardware mode."
	@echo "Please sign the $(Demo_Enclave_Lib) first with your signing key before"
	@echo "you run the $(Demo_App_Name) to launch and access the enclave."
	@echo "To sign the enclave use the command:\n"
	@echo "   $(DEMO_SGX_ENCLAVE_SIGNER) sign -key <your key>"
	@echo "                              -enclave $(Demo_Enclave_Lib)"
	@echo "                              -out <$(Demo_Signed_Enclave_Name)>"
	@echo "                              -config $(Demo_Enclave_Config_File)\n"
	@echo "You can also sign the enclave using an external signing tool."
	@echo "See User's Guide for more details."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build"
	@echo "the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."
else
demo-all: demo-pre demo/enclave/$(Demo_Signed_Enclave_Name) $(Demo_App_Name) $(Server_Name) $(Client_Name)
endif


demo-test-keys-certs: demo/data/client_priv_test.pem \
	              demo/data/client_cert_test.pem \
	              demo/data/server_priv_test.pem \
                      demo/data/server_cert_test.pem

demo: demo-all demo-test-keys-certs
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/$(Server_Name) -r demo/data/server_priv_test.pem -u demo/data/client_cert_test.pem -p 7000 &
	@sleep 1
	@$(CURDIR)/$(Demo_App_Name)
	@echo "RUN  =>  $(Demo_App_Name) [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif

test-run: test-all
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/$(Test_App_Name)
	@echo "RUN  =>  $(Test_App_Name) [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif

######## Test Common Objects ########

test/enclave/ec_key_cert_marshal.o: common/src/ec_key_cert_marshal.c
	@$(CC) $(Test_App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

test/enclave/ec_key_cert_unmarshal.o: common/src/ec_key_cert_unmarshal.c
	@$(CC) $(Test_App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

test/enclave/ecdh_util.o: common/src/ecdh_util.c
	@$(CC) $(Test_App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

######## Demo Common Objects ########

demo/enclave/ec_key_cert_marshal.o: common/src/ec_key_cert_marshal.c
	@$(CC) $(Demo_App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

demo/enclave/ec_key_cert_unmarshal.o: common/src/ec_key_cert_unmarshal.c
	@$(CC) $(Demo_App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

demo/enclave/ecdh_util.o: common/src/ecdh_util.c
	@$(CC) $(Demo_App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"


######## Test App Objects ########

test/enclave/log_ocall.o: untrusted/src/ocall/log_ocall.c
	@$(CC) $(Test_App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

test/enclave/memory_ocall.o: untrusted/src/ocall/memory_ocall.c
	@$(CC) $(Test_App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

test/enclave/ecdh_ocall.o: untrusted/src/ocall/ecdh_ocall.c
	@$(CC) $(Test_App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

test/enclave/$(Test_Enclave_Name)_u.c: $(SGX_EDGER8R) test/enclave/$(Test_Enclave_Name).edl
	@cd test/enclave && $(SGX_EDGER8R) --untrusted $(Test_Enclave_Name).edl \
                                      --search-path $(SGX_SDK)/include \
                                      --search-path . \
                                      --search-path ../../trusted \
                                      --search-path $(SGX_SSL_INCLUDE_PATH)
	@echo "GEN  =>  $@"

test/enclave/$(Test_Enclave_Name)_u.o: test/enclave/$(Test_Enclave_Name)_u.c
	@$(CC) $(Test_App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(Test_App_Name): $(Test_App_Source_Files) test/enclave/$(Test_Enclave_Name)_u.o \
                                 test/enclave/ec_key_cert_marshal.o \
                                 test/enclave/ec_key_cert_unmarshal.o \
                                 test/enclave/ecdh_util.o \
                                 test/enclave/ecdh_ocall.o \
                                 test/enclave/memory_ocall.o \
                                 test/enclave/log_ocall.o
	@$(CXX) $^ -o $@ $(Test_App_Cpp_Flags) $(Test_App_Link_Flags) \
	                                  -Lenclave -lcrypto -lcunit
	@echo "LINK =>  $@"



######## Demo App Objects ########

demo/enclave/log_ocall.o: untrusted/src/ocall/log_ocall.c
	@$(CC) $(Demo_App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

demo/enclave/memory_ocall.o: untrusted/src/ocall/memory_ocall.c
	@$(CC) $(Demo_App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

demo/enclave/ecdh_ocall.o: untrusted/src/ocall/ecdh_ocall.c
	@$(CC) $(Demo_App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

demo/enclave/$(Demo_Enclave_Name)_u.c: $(SGX_EDGER8R) demo/enclave/$(Demo_Enclave_Name).edl
	@cd demo/enclave && $(SGX_EDGER8R) --untrusted $(Demo_Enclave_Name).edl \
	                              --search-path $(SGX_SDK)/include \
	                              --search-path . \
	                              --search-path ../../trusted \
	                              --search-path $(SGX_SSL_INCLUDE_PATH)
	@echo "GEN  =>  $@"

demo/enclave/$(Demo_Enclave_Name)_u.o: demo/enclave/$(Demo_Enclave_Name)_u.c
	@$(CC) $(Demo_App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

demo/enclave/$(DEMO_ENCLAVE_HEADER_UNTRUSTED): demo/enclave/$(Demo_Enclave_Name)_u.c

demo/app/%.o: demo/app/%.c demo/enclave/$(DEMO_ENCLAVE_HEADER_UNTRUSTED)
	@$(CC) $(Demo_App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(Demo_App_Name): demo/app/kmyth_sgx_retrieve_key_demo.o \
             demo/enclave/$(Demo_Enclave_Name)_u.o \
             demo/enclave/ec_key_cert_marshal.o \
             demo/enclave/ec_key_cert_unmarshal.o \
             demo/enclave/ecdh_util.o \
             demo/enclave/ecdh_ocall.o \
             demo/enclave/memory_ocall.o \
             demo/enclave/log_ocall.o 
	@$(CXX) $^ -o $@ $(Demo_App_Cpp_Flags) $(Demo_App_Link_Flags)
	@echo "LINK =>  $@"

######## Test Server ########

demo/server/%.o: demo/server/%.c demo/server/ecdh_demo.h
	@$(CC) $(Demo_App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(Server_Name): demo/server/ecdh_server.o \
                demo/server/ecdh_demo.o \
                demo/enclave/ecdh_util.o \
                demo/enclave/log_ocall.o
	@$(CXX) $^ -o $@ $(Demo_App_Cpp_Flags) $(Demo_App_Link_Flags)
	@echo "LINK =>  $@"

$(Client_Name): demo/server/ecdh_client.o \
                demo/server/ecdh_demo.o \
                demo/enclave/ecdh_util.o \
                demo/enclave/log_ocall.o
	@$(CXX) $^ -o $@ $(Demo_App_Cpp_Flags) $(Demo_App_Link_Flags)
	@echo "LINK =>  $@"

######## Test Enclave Objects ########

test/enclave/$(Test_Enclave_Name)_t.c: $(SGX_EDGER8R) test/enclave/$(Test_Enclave_Name).edl
	@cd test/enclave && $(SGX_EDGER8R) --trusted $(Test_Enclave_Name).edl \
		                      --search-path $(SGX_SDK)/include \
                                      --search-path . \
				      --search-path ../../trusted \
                                      --search-path $(SGX_SSL_INCLUDE_PATH)
	@echo "GEN  =>  $@"

test/enclave/$(Test_Enclave_Name)_t.o: test/enclave/$(Test_Enclave_Name)_t.c
	@$(CC) $(Test_Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

test/enclave/kmyth_enclave_memory_util.o: \
		trusted/src/util/kmyth_enclave_memory_util.c 
	@$(CC) $(Test_Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

test/enclave/sgx_retrieve_key_impl.o: \
		trusted/src/wrapper/sgx_retrieve_key_impl.c 
	@$(CC) $(Test_Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

test/enclave/kmyth_sgx_test_trusted.o: test/enclave/kmyth_sgx_test_trusted.c
	@$(CC) $(Test_Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

test/enclave/kmyth_enclave_seal.o: trusted/src/ecall/kmyth_enclave_seal.cpp 
	@$(CC) $(Test_Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

test/enclave/kmyth_enclave_unseal.o: trusted/src/ecall/kmyth_enclave_unseal.cpp
	@$(CC) $(Test_Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

test/enclave/kmyth_enclave_retrieve_key.o: \
		trusted/src/ecall/kmyth_enclave_retrieve_key.cpp
	@$(CC) $(Test_Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

test/enclave/aes_gcm.o: ../src/cipher/aes_gcm.c
	@$(CC) $(Test_Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

test/enclave/memory_util.o: ../utils/src/memory_util.c
	@$(CC) $(Test_Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

test/enclave/kmip_util.o: ../src/protocol/kmip_util.c
	@$(CC) $(Test_Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

test/enclave/$(Test_Enclave_Lib): test/enclave/$(Test_Enclave_Name)_t.o \
                        test/enclave/kmyth_sgx_test_trusted.o \
                        test/enclave/ec_key_cert_marshal.o \
                        test/enclave/ec_key_cert_unmarshal.o \
                        test/enclave/ecdh_util.o \
                        test/enclave/kmyth_enclave_memory_util.o \
                        test/enclave/sgx_retrieve_key_impl.o \
                        test/enclave/kmyth_enclave_seal.o \
                        test/enclave/kmyth_enclave_unseal.o \
                        test/enclave/kmyth_enclave_retrieve_key.o \
                        test/enclave/aes_gcm.o \
                        test/enclave/memory_util.o \
                        test/enclave/kmip_util.o
	@$(CXX) $^ -o $@ $(Test_Enclave_Link_Flags)
	@echo "LINK =>  $@"

test/enclave/$(Test_Enclave_Signing_Key):
	$(error $(err_no_test_enclave_signing_key))

test/enclave/$(Test_Signed_Enclave_Name): test/enclave/$(Test_Enclave_Lib) \
                                test/enclave/$(Test_Enclave_Signing_Key)
	@$(SGX_ENCLAVE_SIGNER) sign -key test/enclave/$(Test_Enclave_Signing_Key) \
		                    -enclave test/enclave/$(Test_Enclave_Lib) \
		                    -out $@ \
	                            -config test/enclave/$(Test_Enclave_Config_File)
	@echo "SIGN =>  $@"

.PHONY: test

test: test-all
	test/bin/kmyth_enclave_tests 2> /dev/null

.PHONY: test-clean

test-clean:
	@rm -f test/enclave/*_t.h test/enclave/*_u.h test/enclave/*_t.c test/enclave/*_u.c
	@rm -f test/enclave/*.o test/enclave/*.so test/enclave/*.pem
	@rm -rf test/bin




######## Demo Enclave Objects ########

demo/enclave/$(Demo_Enclave_Name)_t.c: $(SGX_EDGER8R) demo/enclave/$(Demo_Enclave_Name).edl
	@cd demo/enclave && $(SGX_EDGER8R) --trusted $(Demo_Enclave_Name).edl \
	                              --search-path $(SGX_SDK)/include \
	                              --search-path . \
	                              --search-path ../../trusted \
	                              --search-path $(SGX_SSL_INCLUDE_PATH)
	@echo "GEN  =>  $@"

demo/enclave/$(Demo_Enclave_Name)_t.o: demo/enclave/$(Demo_Enclave_Name)_t.c
	@$(CC) $(Demo_Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

demo/enclave/kmyth_enclave_memory_util.o: trusted/src/util/kmyth_enclave_memory_util.c 
	@$(CC) $(Demo_Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

demo/enclave/sgx_retrieve_key_impl.o: trusted/src/wrapper/sgx_retrieve_key_impl.c 
	@$(CC) $(Demo_Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

demo/enclave/kmyth_enclave_seal.o: trusted/src/ecall/kmyth_enclave_seal.cpp 
	@$(CC) $(Demo_Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

demo/enclave/kmyth_enclave_unseal.o: trusted/src/ecall/kmyth_enclave_unseal.cpp
	@$(CC) $(Demo_Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

demo/enclave/kmyth_enclave_retrieve_key.o: trusted/src/ecall/kmyth_enclave_retrieve_key.cpp
	@$(CC) $(Demo_Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

demo/enclave/aes_gcm.o: ../src/cipher/aes_gcm.c
	@$(CC) $(Demo_Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

demo/enclave/memory_util.o: ../utils/src/memory_util.c
	@$(CC) $(Demo_Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

demo/enclave/kmip_util.o: ../src/protocol/kmip_util.c
	@$(CC) $(Demo_Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

demo/enclave/$(Demo_Enclave_Lib): demo/enclave/$(Demo_Enclave_Name)_t.o \
                        demo/enclave/kmyth_enclave_memory_util.o \
                        demo/enclave/sgx_retrieve_key_impl.o \
                        demo/enclave/ec_key_cert_marshal.o \
                        demo/enclave/ec_key_cert_unmarshal.o \
                        demo/enclave/ecdh_util.o \
                        demo/enclave/kmyth_enclave_seal.o \
                        demo/enclave/kmyth_enclave_unseal.o \
                        demo/enclave/kmyth_enclave_retrieve_key.o \
                        demo/enclave/aes_gcm.o \
                        demo/enclave/memory_util.o \
			demo/enclave/kmip_util.o
	@$(CXX) $^ -o $@ $(Demo_Enclave_Link_Flags)
	@echo "LINK =>  $@"

demo/enclave/$(Demo_Enclave_Signing_Key):
	$(error $(err_no_demo_enclave_signing_key))

demo/enclave/$(Demo_Signed_Enclave_Name): demo/enclave/$(Demo_Enclave_Lib) demo/enclave/$(Demo_Enclave_Signing_Key)
	@$(SGX_ENCLAVE_SIGNER) sign -key demo/enclave/$(Demo_Enclave_Signing_Key) \
	                            -enclave demo/enclave/$(Demo_Enclave_Lib) \
	                            -out $@ \
	                            -config demo/enclave/$(Demo_Enclave_Config_File)
	@echo "SIGN =>  $@"

demo/data/client_priv_test.pem \
demo/data/client_cert_test.pem \
demo/data/server_priv_test.pem \
demo/data/server_cert_test.pem: demo/data/gen_test_keys_certs.bash
	@cd demo/data && ./gen_test_keys_certs.bash
	@echo "GEN => Test Key/Cert Files"

.PHONY: demo-clean

demo-clean:
	@rm -f demo/enclave/*_u.h demo/enclave/*_t.h demo/enclave/*_u.c demo/enclave/*_t.c
	@rm -f demo/enclave/*.o demo/enclave/*.so
	@rm -f demo/enclave/*.pem demo/data/*.pem
	@rm -f demo/server/*.o
	@rm -rf demo/bin
	@rm -f demo/app/*.o
	@rm -f *.log

.PHONY: clean
clean:
	make test-clean
	make demo-clean
