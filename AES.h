#if !defined(AES_H_INCLUDED_)
#define AES_H_INCLUDED_

#define AES_BLOCK_SIZE 16
#define AES_KEYSIZE_256 32

bool AESCBCEncrypt(const unsigned char * key, int keylength, unsigned char * iv, int ivlength, unsigned char * data, unsigned char * ctext, int length);
bool AESCBCEncrypt(const char * key, unsigned char * iv, int ivlength, unsigned char * data, unsigned char * ctext, int length);
bool AESCBCDecrypt(const unsigned char * key, int keylength, unsigned char * iv, int ivlength, unsigned char * ctext, unsigned char * data, int length);
bool AESCBCDecrypt(const char * key, unsigned char * iv, int ivlength, unsigned char * ctext, unsigned char * data, int length);
void HexToBytes(const char *hex, int length, BYTE *bytes);
void BytesToHex(const BYTE *bytes, int length, char *hex);
void BytesToHexLower(const BYTE *bytes, int length, char *hex);

#endif
