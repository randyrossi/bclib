#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <gmp.h>

#include "bcinln.h"

// Flip to 1 to turn on debug output to stderr
int DEBUG = 0;

unsigned char alphabet[] = 
     "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

int reverseMap[128];

void init_bclib() {
    int i;
    for (i=1; i < 128; i++) {
        unsigned char *f = strchr(alphabet,(char)i);
        if (f != NULL) {
            reverseMap[i] = (int) (f - alphabet);
        } else {
            reverseMap[i] = -1;
        }
    }
}

void ripemd160(unsigned char *string, int len, unsigned char *hash) {
     RIPEMD160_CTX ripemd160;
     RIPEMD160_Init(&ripemd160);
     RIPEMD160_Update(&ripemd160, string, len);
     RIPEMD160_Final(hash, &ripemd160);
}

void sha256(unsigned char *string, int len, unsigned char *hash) {
     SHA256_CTX sha256;
     SHA256_Init(&sha256);
     SHA256_Update(&sha256,string, len);
     SHA256_Final(hash, &sha256);
}

unsigned char* hexToBytes(unsigned char* input,int *size) {

     if (input == NULL) {
         return NULL;
     }

     int len = strlen((char*) input);
     if (len % 2 != 0) {
         return NULL;
     }

     unsigned char *output = (unsigned char*) malloc(len / 2);

     int v = 0;

     int i;
     int dest=0;
     for (i=0; i < len; i+=2) {
         char h1 = input[i + 1];
         char h2 = input[i];

         if (!isxdigit(h1) || !isxdigit(h2)) {
             free(output);
             return NULL;
         }

         unsigned int val = hexDigitToDecimal(h1) + hexDigitToDecimal(h2) * 16;
         output[dest] = val;

         dest++;
     }

     if (size != NULL) {
         *size = len / 2;
     }

     return output;
}

unsigned char* bytesToHex(unsigned char* input,int num) {

     unsigned char *output = (unsigned char*) malloc(num * 2 + 1);

     int i;
     int j=0;
     for (i=0; i < num; i++) {
         unsigned int val = input[i] & 0xff;
         unsigned int h1 = val / 16;
         unsigned int h2 = val % 16;

         output[j] = decDigitToHex(h1);
         output[j+1] = decDigitToHex(h2);

         j += 2;
     }

     // null terminate it
     output[j] = '\0';

     return output;
}

void reverse(char s[],int length) {

     int c, i, j;

     for (i = 0, j = length - 1; i < j; i++, j--) {
         c = s[i];
         s[i] = s[j];
         s[j] = c;
     }
}

unsigned char *base58(mpz_t in,unsigned char *inBytes, int size) {

     unsigned int base_count = strlen(alphabet);
     mpz_t q;
     mpz_t r;
     unsigned int r_ui;
     int j,k;
     int p = 0;

     unsigned char *dest = (unsigned char*) malloc(256);

     mpz_init(q);
     mpz_init(r);
 
     while (mpz_cmp_ui(in, base_count) >= 0) {
         mpz_fdiv_qr_ui(q,r,in,base_count);

         r_ui = mpz_get_ui(r);

         dest[p++] = alphabet[r_ui];
         mpz_set(in,q);
     }

     if (mpz_cmp_ui(in,0) > 0) {
         r_ui = mpz_get_ui(in);
         dest[p++] = alphabet[r_ui];
     }

     j=0;
     while (inBytes[j] == 0 && j < size) {
         dest[p++] = alphabet[0];
         j++;
     }

     dest[p++] = 0;
     k = p - 1; // length of string

     reverse(dest,k);

     mpz_clear(r);
     mpz_clear(q);

     return dest;
}

unsigned char* fromBase58(unsigned char *str) {
     
     unsigned char *buf = (unsigned char*) malloc(1024);

     mpz_t n;
     mpz_t m;
     mpz_t t;
     mpz_init(n);
     mpz_init(m);
     mpz_init(t);
     mpz_set_ui(n,0);
     mpz_set_ui(m,1);
     mpz_set_ui(t,0);

     int i;
     int error = 0;
     for (i=strlen(str) - 1; i>=0; i--) {

         int b58Char = (int)str[i];
         if (b58Char <= 0 || b58Char >= 128) {
             error = 1;
             break;
         }
         unsigned long v = reverseMap[b58Char];
         if (v == -1) {
             error = 1;
             break;
         }
         mpz_mul_ui(t, m, v);
         mpz_add(n, n, t);
         mpz_mul_ui(m, m, 58);
     }

     //mpz_out_str(NULL, 16, n);

     if (!error) {
         gmp_snprintf(buf, 1024, "%Zx", n);
     }

     mpz_clear(n);
     mpz_clear(m);
     mpz_clear(t);

     if (error) {
         free(buf);
         return NULL;
     } else {
         return buf;
     }
}

unsigned char* genaddress(unsigned char *inputHex) {
    unsigned char *tmp;
    char output[65];

    if (DEBUG) {
       fprintf (stderr,"STEP1: %s\n",inputHex);
    }

    int size;
    unsigned char* step1 = hexToBytes((unsigned char*) inputHex, &size);

    unsigned char step2[SHA256_DIGEST_LENGTH];
    sha256(step1, size, step2);
    free(step1);

    if (DEBUG) {
        tmp = bytesToHex(step2, SHA256_DIGEST_LENGTH);
        fprintf (stderr, "STEP2: %s\n",tmp);
        free(tmp);
    }

    unsigned char step3[RIPEMD160_DIGEST_LENGTH];
    ripemd160(step2, SHA256_DIGEST_LENGTH, step3);

    if (DEBUG) {
        tmp = bytesToHex(step3, RIPEMD160_DIGEST_LENGTH);
        fprintf (stderr, "STEP3: %s\n", tmp);
        free(tmp);
    }

    unsigned char *step4 = (unsigned char*) malloc(RIPEMD160_DIGEST_LENGTH + 1);
    step4[0] = 0;
    memcpy(step4+1, step3, RIPEMD160_DIGEST_LENGTH);

    if (DEBUG) {
        tmp = bytesToHex(step4, RIPEMD160_DIGEST_LENGTH + 1);
        fprintf (stderr, "STEP4: %s\n", tmp);
        free(tmp);
    }

    unsigned char step5[SHA256_DIGEST_LENGTH];
    sha256(step4, RIPEMD160_DIGEST_LENGTH + 1, step5);

    if (DEBUG) {
        tmp = bytesToHex(step5, SHA256_DIGEST_LENGTH);
        fprintf (stderr, "STEP5: %s\n", tmp);
        free(tmp);
    }

    unsigned char step6[SHA256_DIGEST_LENGTH];
    sha256(step5, SHA256_DIGEST_LENGTH, step6);

    if (DEBUG) {
        tmp = bytesToHex(step6, SHA256_DIGEST_LENGTH);
        fprintf (stderr, "STEP6: %s\n", tmp);
        free(tmp);
    } 

    unsigned char step7[4]; 
    memcpy(step7, step6, 4);
 
    if (DEBUG) {
        tmp = bytesToHex(step7, 4);
        fprintf (stderr, "STEP7: %s\n", tmp);
        free(tmp);
    }

    unsigned int step8Size = RIPEMD160_DIGEST_LENGTH + 1 + 4;
    unsigned char step8[RIPEMD160_DIGEST_LENGTH + 1 + 4];
    memcpy(step8, step4, RIPEMD160_DIGEST_LENGTH + 1);
    free(step4);
    memcpy(step8 + RIPEMD160_DIGEST_LENGTH + 1, step7, 4);
    unsigned char *step8Str = bytesToHex(step8, step8Size);

    if (DEBUG) {
        fprintf (stderr, "STEP8: %s\n", step8Str);
    }

    mpz_t integ;
    mpz_init (integ);
    mpz_set_str(integ, step8Str, 16);

    unsigned char *address = base58(integ, step8, step8Size);

    if (DEBUG) {
        printf ("ADDRESS: %s\n", address);
    }

    free(step8Str);

    mpz_clear(integ);
    return address;
}

int EC_KEY_regenerate_key(EC_KEY *eckey, BIGNUM *priv_key)
{
    int ok = 0;
    BN_CTX *ctx = NULL;
    EC_POINT *pub_key = NULL;

    if (!eckey) return 0;

    const EC_GROUP *group = EC_KEY_get0_group(eckey);

    if ((ctx = BN_CTX_new()) == NULL)
        goto err;

    pub_key = EC_POINT_new(group);

    if (pub_key == NULL)
        goto err;

    if (!EC_POINT_mul(group, pub_key, priv_key, NULL, NULL, ctx))
        goto err;

    EC_KEY_set_private_key(eckey,priv_key);
    EC_KEY_set_public_key(eckey,pub_key);

    ok = 1;

err:

    if (pub_key)
        EC_POINT_free(pub_key);
    if (ctx != NULL)
        BN_CTX_free(ctx);

    return(ok);
}

unsigned char* secretBytesToPrivate(unsigned char* secret, int len,
         int compressed) {

    if (secret == NULL) {
        return NULL;
    }

    if (compressed) {
        len++;
    }

    unsigned char *step2;
    step2 = (unsigned char*) malloc(len + 1);

    step2[0] = 0x80;
    memcpy(step2 + 1, secret, len);
    if (compressed) {
        step2[len] = 1;
    }
    
    unsigned char step3[SHA256_DIGEST_LENGTH];
    sha256(step2, len + 1, step3);

    unsigned char step4[SHA256_DIGEST_LENGTH];
    sha256(step3, SHA256_DIGEST_LENGTH, step4);

    unsigned char *step5 = (unsigned char *) malloc(len + 1 + 4);
    memcpy(step5, step2, len + 1);
    memcpy(step5 + len + 1, step4, 4);

    unsigned char *secretHex2 = bytesToHex(step5, len + 1 + 4);
  
    mpz_t integ;
    mpz_init (integ);
    mpz_set_str(integ, secretHex2, 16);

    unsigned char *secretB58 = base58(integ, step5, len + 1 + 4);

    mpz_clear(integ);
    free(step2);
    free(step5);
    free(secretHex2);

    return secretB58;
}

unsigned char* secretHexToPrivate(unsigned char* secretHex, int compressed) {

    int len;
    unsigned char *secret = hexToBytes(secretHex, &len);

    if (secret == NULL) {
        return NULL;
    }

    unsigned char *ret = secretBytesToPrivate(secret, len, compressed); 
    free(secret);

    return ret;
}

unsigned char* secretBytesToRawPublic(unsigned char* secret, int size,
         int *rawLen, int compressed) {

    EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_secp256k1);

    BIGNUM *bn = BN_bin2bn(secret, size, BN_new());

    int ok = EC_KEY_regenerate_key(eckey, bn);
    if (ok == 0) {
        if (DEBUG) {
            fprintf (stderr,"could not gen key\n");
        }
        return NULL;
    }

    unsigned char *buf = (unsigned char*) malloc(1024);

    BN_clear_free(bn);

    if (compressed) {
        EC_KEY_set_conv_form(eckey, POINT_CONVERSION_COMPRESSED);
    }

    unsigned char* pptr = &buf[0];
    *rawLen = i2o_ECPublicKey(eckey, &pptr);

    EC_KEY_free(eckey);

    return buf;
}

unsigned char* secretBytesToPublic(unsigned char* secret, int size,
         int compressed) {

    int rawLen;

    if (secret == NULL) {
        return NULL;
    }

    unsigned char* secretRaw = secretBytesToRawPublic(secret, size, &rawLen,
         compressed);

    if (secretRaw == NULL) {
        return NULL;
    }

    unsigned char* publicHex = bytesToHex(secretRaw, rawLen);
    free(secretRaw);

    if (publicHex == NULL) {
        return NULL;
    }

    if (DEBUG) {
       fprintf (stderr, "PUBLIC: %s\n", publicHex);
    }

    unsigned char *address = genaddress(publicHex);

    free(publicHex);

    if (DEBUG) {
       fprintf (stderr,"ADDRESS: %s\n", address);
    }

    return address;
}

unsigned char* secretHexToPublic(unsigned char* secretHex, int compressed) {
    if (DEBUG) {
       fprintf (stderr, "SECRET: %s\n", secretHex);
    }

    int size;
    unsigned char *secret = hexToBytes(secretHex, &size);
    if (secret == NULL) {
        return NULL;
    }

    unsigned char *ret = secretBytesToPublic(secret, size, compressed);
    free(secret);

    return ret;
}
