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

######### Source Code Indentation Settings ###################################

INDENT_OPTS = -bli0#                     indent braces zero spaces
INDENT_OPTS += -bap#                     blank lines after procedure bodies
INDENT_OPTS += -bad#                     blank lines after declarations
INDENT_OPTS += -sob#                     swallow optional blank lines
INDENT_OPTS += -cli0#                    case label indent of zero spaces
INDENT_OPTS += -npcs#                    no space after function in calls
INDENT_OPTS += -nbc#                     don't force newlines after commas
INDENT_OPTS += -bls#                     put braces on line after struct decl
INDENT_OPTS += -blf#                     put braces on line after func def
INDENT_OPTS += -lp#                      align continued lines at parentheses
INDENT_OPTS += -ip0#                     indent parameter types zero spaces
INDENT_OPTS += -ts2#                     set tab size to two spaces
INDENT_OPTS += -nut#                     use spaces instead of tabs
INDENT_OPTS += -npsl#                    type of proc on same line as name
INDENT_OPTS += -bbo#                     prefer break before boolean operator
INDENT_OPTS += -l80#                     max non-comment line length is 80


######## SGX SDK Build Settings ########

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= SIM
SGX_ARCH ?= x64
SGX_SSL_UNTRUSTED_LIB_PATH ?= /opt/intel/sgxssl/lib64/
SGX_SSL_TRUSTED_LIB_PATH ?= /opt/intel/sgxssl/lib64/
SGX_SSL_INCLUDE_PATH ?= /opt/intel/sgxssl/include/

ENCLAVE_HEADER_TRUSTED ?= '"kmyth_sgx_retrieve_key_demo_enclave_t.h"'
ENCLAVE_HEADER_UNTRUSTED ?= '"kmyth_sgx_retrieve_key_demo_enclave_u.h"'

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

App_Name := bin/kmyth_sgx_retrieve_key_demo

App_Source_Files := app/kmyth_sgx_retrieve_key_demo.c

App_Include_Paths := -Iinclude
App_Include_Paths += -I../untrusted/include/ocall
App_Include_Paths += -I../untrusted/include/util
App_Include_Paths += -I../untrusted/include/wrapper
App_Include_Paths += -I../common/include
App_Include_Paths += -Ienclave
App_Include_Paths += -Iserver/include
App_Include_Paths += -I$(SGX_SDK)/include
App_Include_Paths += -I../../include/network
App_Include_Paths += -I../../include/protocol

App_C_Flags := $(SGX_COMMON_CFLAGS)
App_C_Flags += -fPIC -Wno-attributes
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
App_Link_Flags += -l$(Urts_Library_Name)
App_Link_Flags += -Lenclave
App_Link_Flags += -lsgx_usgxssl

ifneq ($(SGX_MODE), HW)
	App_Link_Flags += -lsgx_uae_service_sim
else
	App_Link_Flags += -lsgx_uae_service
endif

App_Link_Flags += -lpthread
App_Link_Flags += -lkmyth-utils
App_Link_Flags += -lkmyth-logger
App_Link_Flags += -lkmyth-tpm
App_Link_Flags += -lcrypto

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

Enclave_C_Flags := -Wall
Enclave_C_Flags += $(SGX_COMMON_CFLAGS)
Enclave_C_Flags += -nostdinc
Enclave_C_Flags += -fvisibility=hidden
Enclave_C_Flags += -fpie
Enclave_C_Flags += -fstack-protector
Enclave_C_Flags += $(Enclave_Include_Paths)
Enclave_C_Flags += -DENCLAVE_HEADER_TRUSTED=$(ENCLAVE_HEADER_TRUSTED)

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
Enclave_Link_Flags += -L/usr/local/lib
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
Enclave_Link_Flags += -lkmip-core

Enclave_Name := kmyth_sgx_retrieve_key_demo_enclave
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

######## Demo Server Build Settings ########

Server_Name := bin/ecdh-server
Client_Name := bin/ecdh-client

# Message for missing Enclave Signing Key - Fatal Build Error
define err_no_enclave_signing_key
FAIL - No Enclave Signing Key found
Generate or install build/$(Enclave_Signing_Key)
e.g., run 'openssl genrsa -out sgx/$(Enclave_Signing_Key) -3 3072'
endef

.PHONY: all pre test-keys-certs demo

ifeq ($(Build_Mode), HW_RELEASE)
all: pre $(Enclave_Lib) $(App_Name) $(Server_Name) $(Client_Name)
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
all: pre enclave/$(Signed_Enclave_Name) $(App_Name) $(Server_Name) $(Client_Name)
endif

pre:
	@mkdir -p bin 
	@if [ ! -f enclave/$(Enclave_Signing_Key) ]; then \
	   openssl genrsa -out enclave/$(Enclave_Signing_Key) -3 3072; \
	 fi
	@indent $(INDENT_OPTS) app/*.c
	@indent $(INDENT_OPTS) server/*.c server/*.h
	@indent $(INDENT_OPTS) ../untrusted/src/*/*.c ../untrusted/include/*/*.h
	@indent $(INDENT_OPTS) ../trusted/src/*/*.cpp ../trusted/src/*/*.c
	@indent $(INDENT_OPTS) ../trusted/include/*.h ../trusted/include/util/*.h
	@rm -f app/*~
	@rm -f ../untrusted/src/*/*~ ../untrusted/include/*/*~
	@rm -f ../trusted/src/*/*~ ../trusted/include/*~ ../trusted/include/*/*~

test-keys-certs: data/client_priv_test.pem \
	               data/client_cert_test.pem \
                 data/server_priv_test.pem \
                 data/server_cert_test.pem

demo: all test-keys-certs
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/$(Server_Name) -r data/server_priv_test.pem -u data/client_cert_test.pem -p 7000 &
	@sleep 1
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

enclave/ecdh_dummy_server.o: ../untrusted/src/util/ecdh_dummy_server.c
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

enclave/$(ENCLAVE_HEADER_UNTRUSTED): enclave/$(Enclave_Name)_u.c

app/%.o: app/%.c enclave/$(ENCLAVE_HEADER_UNTRUSTED)
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(App_Name): app/kmyth_sgx_retrieve_key_demo.o \
             enclave/$(Enclave_Name)_u.o \
             enclave/ec_key_cert_marshal.o \
             enclave/ec_key_cert_unmarshal.o \
             enclave/ecdh_util.o \
             enclave/ecdh_ocall.o \
             enclave/ecdh_dummy_server.o \
             enclave/memory_ocall.o \
             enclave/log_ocall.o 
	@$(CXX) $^ -o $@ $(App_Cpp_Flags) $(App_Link_Flags)
	@echo "LINK =>  $@"

######## Test Server ########

server/%.o: server/%.c server/ecdh_demo.h
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(Server_Name): server/ecdh_server.o \
                server/ecdh_demo.o \
                enclave/ecdh_util.o \
                enclave/log_ocall.o
	@$(CXX) $^ -o $@ $(App_Cpp_Flags) $(App_Link_Flags)
	@echo "LINK =>  $@"

$(Client_Name): server/ecdh_client.o \
                server/ecdh_demo.o \
                enclave/ecdh_util.o \
                enclave/log_ocall.o
	@$(CXX) $^ -o $@ $(App_Cpp_Flags) $(App_Link_Flags)
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

enclave/kmyth_enclave_memory_util.o: ../trusted/src/util/kmyth_enclave_memory_util.c 
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

enclave/sgx_retrieve_key_impl.o: ../trusted/src/wrapper/sgx_retrieve_key_impl.c 
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

enclave/$(Enclave_Lib): enclave/$(Enclave_Name)_t.o \
                        enclave/kmyth_enclave_memory_util.o \
                        enclave/sgx_retrieve_key_impl.o \
                        enclave/ec_key_cert_marshal.o \
                        enclave/ec_key_cert_unmarshal.o \
                        enclave/ecdh_util.o \
                        enclave/kmyth_enclave_seal.o \
                        enclave/kmyth_enclave_unseal.o \
                        enclave/kmyth_enclave_retrieve_key.o
	@$(CXX) $^ -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

enclave/$(Enclave_Signing_Key):
	$(error $(err_no_enclave_signing_key))

enclave/$(Signed_Enclave_Name): enclave/$(Enclave_Lib) enclave/$(Enclave_Signing_Key)
	@$(SGX_ENCLAVE_SIGNER) sign -key enclave/$(Enclave_Signing_Key) \
	                            -enclave enclave/$(Enclave_Lib) \
	                            -out $@ \
	                            -config enclave/$(Enclave_Config_File)
	@echo "SIGN =>  $@"

data/client_priv_test.pem \
data/client_cert_test.pem \
data/server_priv_test.pem \
data/server_cert_test.pem: data/gen_test_keys_certs.bash
	@cd data && ./gen_test_keys_certs.bash
	@echo "GEN => Test Key/Cert Files"

.PHONY: clean

clean:
	@rm -f enclave/*_u.h enclave/*_t.h enclave/*_u.c enclave/*_t.c
	@rm -f enclave/*.o enclave/*.so
	@rm -f enclave/*.pem data/*.pem
	@rm -f server/*.o
	@rm -rf bin
