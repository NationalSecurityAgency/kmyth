//############################################################################
// kmyth_test_cipher.c
//
// General utilities for kmyth cipher testing:
//   - convert hexadecimal valued strings in vector files to byte arrays
//############################################################################

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "kmyth_cipher_test.h"


//----------------------------------------------------------------------------
// convert_HexString_to_ByteArray()
//----------------------------------------------------------------------------
int convert_HexString_to_ByteArray(char **result, char *hex_str, int str_size)
{
  if((str_size % 2) != 0)
  {
    fprintf(stderr, "ERROR: Invalid hex string size, must be even.\n");
    return 1; 
  }

  size_t bufSize = ((str_size) / 2);
  char * buf = (char *) calloc(bufSize + 1, sizeof(char)); 
  for (int i = 0; i < bufSize; i++)
  {
    sscanf(hex_str+(i*2), "%02hhx", &buf[i]);
  }
  buf[bufSize] = '\0';

  *result = buf;

  return 0;
}

