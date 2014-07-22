#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "bclib.h"

int run_tests() {
    int numBytes;

    unsigned char *asHex;

    //
    // fromBase58() - bad input
    //
    asHex = fromBase58("Lbwb5yufe3TCSvjwoAUrk9FORe7aeJ62YTo6ABDiFts7ovY8tcak");
    assert(asHex == NULL);

    //
    // fromBase58() - good input
    //
    asHex = fromBase58("Lbwb5yufe3TCSvjwoAUrk9FzRe7aeJ62YTo6ABDiFts7ovY8tcak");
    assert(asHex != NULL);
    assert(strlen(asHex) == 76);
    assert(strncmp(
        "84835d5042486a38e5e93345649ace3943efddc643b3c0ecc3d144e654113682ce7d4882f799",
            asHex, 76) == 0);
    unsigned char keyHex[65];
    memcpy (keyHex, asHex + 2, 64);
    keyHex[64] = '\0';
    free(asHex);

    //
    // bytesToHex(hexToBytes(str)) == str
    //
    char *inputHex = 
        "0450863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B2355";
    unsigned char* inputBytes = 
        hexToBytes((unsigned char*) inputHex, &numBytes);
    unsigned char* outputHex = bytesToHex(inputBytes, numBytes);
    assert (inputBytes != NULL);
    assert (outputHex != NULL);
    assert (strncmp((char*)inputHex, (char*) outputHex, strlen(inputHex)) == 0);
    free(inputBytes);
    free(outputHex);

    //
    // hexToBytes - bad input
    //
    unsigned char* secret;
    secret = hexToBytes("A", &numBytes);
    assert(secret == NULL);
    secret = hexToBytes("AG", &numBytes);
    assert(secret == NULL);

    //
    // hexToBytes - good input
    //
    secret = hexToBytes(keyHex, &numBytes);
    assert(secret != NULL);
    assert(numBytes == 32);

    unsigned char *privateB58U;
    unsigned char *publicB58U;
    unsigned char *privateB58C;
    unsigned char *publicB58C;

    privateB58U = secretBytesToPrivate(secret, 32, 0);
    publicB58U = secretBytesToPublic(secret, 32, 0);
    assert(privateB58U != NULL);
    assert(publicB58U != NULL);
    assert(strncmp(privateB58U, 
        "5Jp97RMBQfEy5xDCuz59HQzL8TMPGmrsVvzT37zAotrE53brxHx",
            strlen(privateB58U)) == 0);
    assert(strncmp(publicB58U, 
        "1LEyj89YU4qGfFk7dc1jpGAYX5DhQm9moP",
            strlen(publicB58U)) == 0);
   
    privateB58C = secretBytesToPrivate(secret, 32, 1);
    publicB58C = secretBytesToPublic(secret, 32, 1);
    assert(privateB58C != NULL);
    assert(publicB58C != NULL);
    assert(strncmp(privateB58C, 
        "L1d4oLU4wRneYrgsaruHZSt3RuJyJd17thJZvMqLHyrGgMq74H5L",
            strlen(privateB58C)) == 0);
    assert(strncmp(publicB58C, 
        "1PaJnioooVnq5oMgF4wYNer6rVyxZLaTqf",
            strlen(publicB58C)) == 0);

    free(secret);
    free(privateB58U);
    free(publicB58U);
    free(privateB58C);
    free(publicB58C);
}

int main(int argc,char* argv[]) {
    init_bclib();

    // Run in an endless loop to find memory leaks.
    run_tests();

    printf ("All tests passed\n");
}
