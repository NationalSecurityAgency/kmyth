# Makefile for Kmyth
PREFIX = /usr/local

CC = gcc -std=c11
DEBUG = -g

INCLUDES = 
LLIBS = 
CFLAGS = -Wall -c $(DEBUG) -D_XOPEN_SOURCE=700 $(INCLUDES) 
LFLAGS = -Wall $(DEBUG) -ltspi -lcrypto -lssl

OBJ_DIR = objs
SRC_DIR = src
TEST_DIR = test

INCLUDE_DIR = include

UTIL_SRC_DIR = $(SRC_DIR)/util
UTIL_OBJ_DIR = $(OBJ_DIR)/util

SEAL_SRC_DIR = $(SRC_DIR)/seal
SEAL_OBJ_DIR = $(OBJ_DIR)/seal

UNSEAL_SRC_DIR = $(SRC_DIR)/unseal
UNSEAL_OBJ_DIR = $(OBJ_DIR)/unseal

GETKEY_SRC_DIR = $(SRC_DIR)/getkey
GETKEY_OBJ_DIR = $(OBJ_DIR)/getkey

HEADER_FILES = $(wildcard $(INCLUDE_DIR)/*h)

UTIL_SOURCES = $(wildcard $(UTIL_SRC_DIR)/*c)
UTIL_OBJECTS = $(subst $(UTIL_SRC_DIR), $(UTIL_OBJ_DIR), $(UTIL_SOURCES:%.c=%.o))

SEAL_SOURCES = $(wildcard $(SEAL_SRC_DIR)/*.c)
SEAL_OBJECTS = $(subst $(SEAL_SRC_DIR), $(SEAL_OBJ_DIR), $(SEAL_SOURCES:%.c=%.o))

UNSEAL_SOURCES = $(wildcard $(UNSEAL_SRC_DIR)/*.c)
UNSEAL_OBJECTS = $(subst $(UNSEAL_SRC_DIR), $(UNSEAL_OBJ_DIR), $(UNSEAL_SOURCES:%.c=%.o))

GETKEY_SOURCES = $(wildcard $(GETKEY_SRC_DIR)/*.c)
GETKEY_OBJECTS = $(subst $(GETKEY_SRC_DIR), $(GETKEY_OBJ_DIR), $(GETKEY_SOURCES:%.c=%.o))

TEST_SOURCES =  $(wildcard $(TEST_DIR)/*.c)

OBJECTS= $(SEAL_OBJECTS) $(UNSEAL_OBJECTS) $(UTIL_OBJECTS) $(GETKEY_OBJECTS)

all: pre kmyth-seal kmyth-unseal kmyth-getkey

kmyth-seal: $(SEAL_OBJECTS) $(UTIL_OBJECTS)
	$(CC) $(SEAL_OBJECTS) $(UTIL_OBJECTS) -o bin/kmyth-seal $(LLIBS) $(LFLAGS)

kmyth-unseal: $(UNSEAL_OBJECTS) $(UTIL_OBJECTS)
	$(CC) $(UNSEAL_OBJECTS) $(UTIL_OBJECTS) -o bin/kmyth-unseal $(LLIBS) $(LFLAGS)

kmyth-getkey: $(GETKEY_OBJECTS) $(UTIL_OBJECTS)
	$(CC) $(GETKEY_OBJECTS) $(UTIL_OBJECTS) -o bin/kmyth-getkey $(LLIBS) $(LFLAGS)

testrunner: $(UTIL_OBJECTS) $(TEST_SOURCES)
	$(CC) $(UTIL_OBJECTS) $(TEST_SOURCES) -o bin/kmyth-testrunner $(LLIBS) -lcunit $(LFLAGS) -I$(INCLUDE_DIR) 

pre:
	indent -bli0 -bap -bad -sob -cli0 -npcs -nbc -bls -blf -nlp -ip0 -ts2 -nut -npsl -bbo -l128 src/*/*.c
	indent -bli0 -bap -bad -sob -cli0 -npcs -nbc -bls -blf -nlp -ip0 -ts2 -nut -npsl -bbo -l128 include/*.h
	rm src/*/*.c~
	rm include/*.h~
	mkdir -p bin

test: testrunner
	./bin/kmyth-testrunner 2> /dev/null

docs: $(HEADER_FILES) $(UTIL_SOURCES) $(TOOL_SOURCES) $(SEAL_SOURCES) $(UNSEAL_SOURCES) $(GETKEY_SOURCES) Doxyfile
	doxygen Doxyfile 

#These commands.... probably could be one. 
$(SEAL_OBJ_DIR)/%.o: $(SEAL_SRC_DIR)/%.c | $(SEAL_OBJ_DIR) 
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -c $< -o $@

$(UNSEAL_OBJ_DIR)/%.o: $(UNSEAL_SRC_DIR)/%.c | $(UNSEAL_OBJ_DIR)
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -c $< -o $@

$(UTIL_OBJ_DIR)/%.o: $(UTIL_SRC_DIR)/%.c | $(UTIL_OBJ_DIR)
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -c $< -o $@

$(GETKEY_OBJ_DIR)/%.o: $(GETKEY_SRC_DIR)/%.c | $(GETKEY_OBJ_DIR)
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -c $< -o $@

$(SEAL_OBJ_DIR):
	mkdir -p $(OBJ_DIR) $(SEAL_OBJ_DIR)

$(UNSEAL_OBJ_DIR):
	mkdir -p $(OBJ_DIR) $(UNSEAL_OBJ_DIR)

$(UTIL_OBJ_DIR):
	mkdir -p $(OBJ_DIR) $(UTIL_OBJ_DIR)

$(GETKEY_OBJ_DIR):
	mkdir -p $(OBJ_DIR) $(GETKEY_OBJ_DIR)

.PHONY: install
install:
	mkdir -p $(PREFIX)/bin
	cp bin/kmyth-seal $(PREFIX)/bin
	cp bin/kmyth-unseal $(PREFIX)/bin
	cp bin/kmyth-getkey $(PREFIX)/bin

.PHONY: uninstall
uninstall:
	rm -f $(PREFIX)/bin/kmyth-seal
	rm -f $(PREFIX)/bin/kmyth-unseal
	rm -f $(PREFIX)/bin/kmyth-getkey

clean:
	-rm -fr $(OBJECTS) bin/kmyth-seal bin/kmyth-unseal bin/kmyth-getkey bin/kmyth-testrunner
