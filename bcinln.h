#ifndef BCINLN_H
#define BCINLN_H

static inline unsigned char decDigitToHex(int val)
{
    static char chars[17] = "0123456789ABCDEF";
    return (unsigned char)chars[val];
}

static inline unsigned int hexDigitToDecimal(char digit)
{
    if (digit >='0' && digit <='9') {
	return digit-'0';
    } else if (digit >='a' && digit <='f') {
	return digit-'a'+10;
    } else if (digit >='A' && digit <='F') {
	return digit-'A'+10;
    } else {
	fprintf (stderr,"invalid hex digit %c\n",digit);
        exit(-1);
    }
}

#endif
