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

######## SGX SDK Settings ########

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= SIM
SGX_ARCH ?= x64

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

######## App Settings ########

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

App_Name := bin/kmyth_enclave_tests

App_Cpp_Files := src/kmyth_enclave_tests.c

App_Include_Paths := -Iinclude -Isgx -I$(SGX_SDK)/include 

App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Include_Paths) -DPELZ_SGX_UNTRUSTED

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
App_Link_Flags := $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name)

ifneq ($(SGX_MODE), HW)
	App_Link_Flags += -lsgx_uae_service_sim
else
	App_Link_Flags += -lsgx_uae_service
endif

App_Name := pelz-sgx

App_Name_Test := pelz-test

######## Enclave Settings ########

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif
Crypto_Library_Name := sgx_tcrypto

Enclave_Include_Paths := -I../kmyth_enclave -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport 

Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(Enclave_Include_Paths)
Enclave_Cpp_Flags := $(Enclave_C_Flags) -std=c++03 -nostdinc++ --include 
Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_pthread -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \

Enclave_Name := kmyth_test_enclave.so
Enclave_Signing_Key := kmyth_test_enclave_private.pem
Signed_Enclave_Name := kmyth_test_enclave.signed.so
Enclave_Config_File := kmyth_test_enclave.config.xml

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
Generate or install sgx/$(Enclave_Signing_Key)
e.g., run 'openssl genrsa -out sgx/$(Enclave_Signing_Key) -3 3072'
endef


.PHONY: all run

ifeq ($(Build_Mode), HW_RELEASE)
all: $(App_Name) $(Enclave_Name)
	@echo "The project has been built in release hardware mode."
	@echo "Please sign the $(Enclave_Name) first with your signing key before you run the $(App_Name) to launch and access the enclave."
	@echo "To sign the enclave use the command:"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <your key> -enclave $(Enclave_Name) -out <$(Signed_Enclave_Name)> -config $(Enclave_Config_File)"
	@echo "You can also sign the enclave using an external signing tool. See User's Guide for more details."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."
else
all: bin/$(App_Name) test/bin/$(App_Name_Test) sgx/$(Signed_Enclave_Name)
endif

run: all
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/$(App_Name)
	@echo "RUN  =>  $(App_Name) [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif

######## App Objects ########

sgx/pelz_enclave_u.c: $(SGX_EDGER8R) sgx/pelz_enclave.edl
	@cd sgx && $(SGX_EDGER8R) --untrusted pelz_enclave.edl --search-path . --search-path include --search-path $(SGX_SDK)/include --search-path $(SGX_SSL_INCLUDE_PATH) --search-path ../include
	@echo "GEN  =>  $@"

sgx/pelz_enclave_u.o: sgx/pelz_enclave_u.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

bin/$(App_Name): $(App_Name_File) $(App_Cpp_Files) sgx/pelz_enclave_u.o
	@$(CXX) $^ -o $@ $(App_Cpp_Flags) $(App_Include_Paths) -Isgx $(App_C_Flags) $(App_Link_Flags) -Lsgx -lcrypto -lcjson -lpthread
	@echo "LINK =>  $@"

test/bin/$(App_Name_Test): $(App_Cpp_Test_Files) $(App_Cpp_Files) sgx/pelz_enclave_u.o
	@$(CXX) $^ -o $@ $(App_Cpp_Flags) $(App_Include_Paths) -Itest/include -Isgx $(App_C_Flags) $(App_Link_Flags) -Lsgx -lcrypto -lcjson -lpthread -lcunit
	@echo "LINK =>  $@"

######## Enclave Objects ########

sgx/pelz_enclave_t.c: $(SGX_EDGER8R) sgx/pelz_enclave.edl
	@cd sgx && $(SGX_EDGER8R) --trusted pelz_enclave.edl --search-path . --search-path $(SGX_SDK)/include --search-path $(SGX_SSL_INCLUDE_PATH) --search-path ../include
	@echo "GEN => $@"

sgx/pelz_enclave_t.o: sgx/pelz_enclave_t.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

sgx/key_table.o: src/util/key_table.c
	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

sgx/aes_keywrap_3394nopad.o: src/util/aes_keywrap_3394nopad.c
	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

sgx/pelz_request_handler.o: src/util/pelz_request_handler.c
	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

sgx/charbuf.o: src/util/charbuf.c
	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

sgx/util.o: src/util/util.c
	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <= $<"

sgx/$(Enclave_Name): sgx/pelz_enclave_t.o sgx/key_table.o sgx/aes_keywrap_3394nopad.o sgx/pelz_request_handler.o sgx/charbuf.o sgx/util.o
	@$(CXX) $^ -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

sgx/$(Enclave_Signing_Key):
	$(error $(err_no_enclave_signing_key))

sgx/$(Signed_Enclave_Name): sgx/$(Enclave_Name) sgx/$(Enclave_Signing_Key)
	@$(SGX_ENCLAVE_SIGNER) sign -key sgx/$(Enclave_Signing_Key) -enclave sgx/$(Enclave_Name) -out $@ -config $(Enclave_Config_File)
	@echo "SIGN =>  $@"

.PHONY: test

test: all
	./test/bin/pelz-test 2> /dev/null

.PHONY: clean

clean:
	@rm -f bin/pelz-sgx test/bin/pelz-test sgx/pelz_enclave.signed.so sgx/pelz_enclave.so sgx/*_u.* sgx/*_t.* sgx/*.o test/log/*
