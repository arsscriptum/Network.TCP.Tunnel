#ifndef _SHA256_H_INCLUDED_
#define _SHA256_H_INCLUDED_

#define SHA_SIZE_256 32

void sha256Digest(const unsigned char * data, int length, unsigned char digest[SHA_SIZE_256]);

#endif
