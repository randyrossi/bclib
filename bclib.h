#ifndef BCLIB_H
#define BCLIB_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>

// Initialize the bclib library.
// Must be called before any API methods are invoked.
void init_bclib();

// Convert the given hex string into bytes.
// If not NULL, the number of bytes the hex string represents will be placed
// into 'size'.
// Ownership of the memory allocated is the caller's responsibility.
unsigned char* hexToBytes(unsigned char* input, int *size);

// Convert 'num' bytes pointed to by 'input' into a hex string.
// Ownership of the memory allocated is the caller's responsibility.
unsigned char* bytesToHex(unsigned char* input,int num);

// Convert 'len' bytes pointed to by 'secret' into a base58 formatted
// private key.
// If 'compressed' is non zero, compressed format will be used.
// Ownership of the memory allocated is the caller's responsibility.
unsigned char* secretBytesToPrivate(unsigned char* secret, int len,
        int compressed);

// Convert the hex string pointed to by 'secretHex' into a base58 formatted
// private key.
// The length of secretHex must represent exactly 32 bytes.
// If 'compressed' is non zero, compressed format will be used.
// Ownership of the memory allocated is the caller's responsibility.
unsigned char* secretHexToPrivate(unsigned char* secretHex, int compressed);

// Convert 'size' bytes pointed to by 'secret' into a base58 formatted
// public key.
// Ownership of the memory allocated is the caller's responsibility.
unsigned char* secretBytesToPublic(unsigned char* secret, int size,
        int compressed);

// Convert the hex string pointed to by 'secretHex' into a base58 formatted
// public key.
// If 'compressed' is non zero, compressed format will be used.
// Ownership of the memory allocated is the caller's responsibility.
unsigned char* secretHexToPublic(unsigned char* secretHex, int compressed);

// Convert the given base58 string into a hex string.
// If 'compressed' is non zero, compressed format will be used.
// Ownership of the memory allocated is the caller's responsibility.
unsigned char* fromBase58(unsigned char *str);

#endif
