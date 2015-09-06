/*
tinyTLS project

Copyright 2015 Nesterov A.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/* MASTER.CPP
 * Implementation of TLS 1.0 (RFC 2246) Pseudo-Random-Function.
 * This function is used to compute master secret, key material and 
 * verification values for finished messages
 */
#include <string.h>

#include "hash/hash.h"

//#define TEST_MODULE

/*  From RFC 2246
	TLS 1.0 PRF computation

        PRF(secret, label, seed) = P_MD5(S1, label + seed) ^ P_SHA-1(S2, label + seed);
        L_S = length in bytes of secret;
        L_S1 = L_S2 = ceil(L_S / 2);
		S1 = secret[0 .. L_s1 - 1];
		S2 = secret[L_S - L_S2 .. L_S - 1];

        P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
                               HMAC_hash(secret, A(2) + seed) +
                               HMAC_hash(secret, A(3) + seed) + ...

    A() is defined as:
        A(0) = seed
        A(i) = HMAC_hash(secret, A(i-1))
*/
void PrfGenerateBlock_v1_0(unsigned char * output, unsigned int outLen, const unsigned char * secret, unsigned sectretLen, const char * label, const unsigned char * seed, unsigned int seedLen)
{
	unsigned labelLen = strlen(label);

	unsigned ls2 = (sectretLen + 1) >> 1;

	// first part MD5
	{
		const unsigned char * const secret_begin = secret;
		unsigned int secretKey[16];

		if (sizeof(secretKey) >= ls2) {
			memset(secretKey, 0, sizeof(secretKey));
			memcpy(secretKey, secret_begin, ls2);
		} else {
			//### calculate md5 for hash
			// for now - it's bad condition
			// TLS never uses keys longer than 24 bytes
			return;
		}

		unsigned int A[4];
		unsigned int R[4];

		unsigned char * outPos = output;
		unsigned int outRem = outLen;

		// calculate A1
		HMACMD5_State P_Md5;

		HmacMd5_Init(&P_Md5, secretKey);
		HmacMd5_Update(&P_Md5, (const uint8_t*)label, labelLen);
		HmacMd5_Update(&P_Md5, (const uint8_t*)seed, seedLen);
		HmacMd5_Finish(&P_Md5, A);

		goto after_a1_md5;
	
		do {
			// calculate AN
			HmacMd5(A, secretKey, (const uint8_t*)A, sizeof(A));

		after_a1_md5:

			//### clone the decoder state
			// calculate HMAC
			HmacMd5_Init(&P_Md5, secretKey);
			HmacMd5_Update(&P_Md5, (const uint8_t*)A, sizeof(A));
			HmacMd5_Update(&P_Md5, (const uint8_t*)label, labelLen);
			HmacMd5_Update(&P_Md5, (const uint8_t*)seed, seedLen);
			HmacMd5_Finish(&P_Md5, R);

			if (outRem >= sizeof(R)) {
				memcpy(outPos, R, sizeof(R));
				outRem -= sizeof(R);
				outPos += sizeof(R);
			} else {
				memcpy(outPos, R, outRem);
				outRem = 0;
			}
		} while(outRem > 0);
	}

	// second part SHA1
	{
		const unsigned char * const secret_begin = secret;
		unsigned int secretKey[16];

		if (sizeof(secretKey) >= ls2) {
			memset(secretKey, 0, sizeof(secretKey));
			memcpy(secretKey, secret_begin + (sectretLen - ls2), ls2);
		} else {
			//### calculate sha1 for hash
			// for now - it's bad condition
			// TLS never uses keys longer than 24 bytes
			return;
		}

		unsigned int A[5];
		unsigned int R[5];

		unsigned char * outPos = output;
		unsigned int outRem = outLen;

		// calculate A1
		HMACSHA1_State P_Sha1;

		HmacSha1_Init(&P_Sha1, secretKey);
		HmacSha1_Update(&P_Sha1, (const uint8_t*)label, labelLen);
		HmacSha1_Update(&P_Sha1, (const uint8_t*)seed, seedLen);
		HmacSha1_Finish(&P_Sha1, A);

		goto after_a1_sha1;
	
		do {
			// calculate AN
			HmacSha1(A, secretKey, (const uint8_t*)A, sizeof(A));

		after_a1_sha1:

			//### clone the decoder state
			// calculate HMAC
			HmacSha1_Init(&P_Sha1, secretKey);
			HmacSha1_Update(&P_Sha1, (const uint8_t*)A, sizeof(A));
			HmacSha1_Update(&P_Sha1, (const uint8_t*)label, labelLen);
			HmacSha1_Update(&P_Sha1, (const uint8_t*)seed, seedLen);
			HmacSha1_Finish(&P_Sha1, R);

			{ // a bit more complicated as we need to XOR results
				unsigned l = (outRem >= sizeof(R)) ? sizeof(R) : outRem;
				outRem -= l;
				unsigned char * rPos = (unsigned char *)R;
				for(; l > 0; --l)
				{
					*outPos++ ^= *rPos++;
				}
			}
		} while(outRem > 0);
	}
}

//master_secret = PRF(pre_master_secret, "master secret", ClientHello.random + ServerHello.random)[0..47];
//
//key_block = PRF(SecurityParameters.master_secret, "key expansion", SecurityParameters.server_random + SecurityParameters.client_random);
//
//finished_label = 
//         For Finished messages sent by the client, the string "client finished".
//         For Finished messages sent by the server, the string "server finished".
//verify_data = PRF(master_secret, finished_label, MD5(handshake_messages) + SHA-1(handshake_messages))[0..11];

#ifdef TEST_MODULE

unsigned char pre_master_secret[48] = {
	0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
	0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
	0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
	0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
	0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
	0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab
};

unsigned char test_seed[64] = {
	0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
	0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
	0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
	0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
	0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
	0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
	0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
	0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd
};

unsigned char verify_master_secret[104] = {
	0xD3, 0xD4, 0xD1, 0xE3, 0x49, 0xB5, 0xD5, 0x15, 0x04, 0x46, 0x66, 0xD5, 0x1D, 0xE3, 0x2B, 0xAB,
	0x25, 0x8C, 0xB5, 0x21, 0xB6, 0xB0, 0x53, 0x46, 0x3E, 0x35, 0x48, 0x32, 0xFD, 0x97, 0x67, 0x54,
	0x44, 0x3B, 0xCF, 0x9A, 0x29, 0x65, 0x19, 0xBC, 0x28, 0x9A, 0xBC, 0xBC, 0x11, 0x87, 0xE4, 0xEB,
	0xD3, 0x1E, 0x60, 0x23, 0x53, 0x77, 0x6C, 0x40, 0x8A, 0xAF, 0xB7, 0x4C, 0xBC, 0x85, 0xEF, 0xF6,
	0x92, 0x55, 0xF9, 0x78, 0x8F, 0xAA, 0x18, 0x4C, 0xBB, 0x95, 0x7A, 0x98, 0x19, 0xD8, 0x4A, 0x5D,
	0x7E, 0xB0, 0x06, 0xEB, 0x45, 0x9D, 0x3A, 0xE8, 0xDE, 0x98, 0x10, 0x45, 0x4B, 0x8B, 0x2D, 0x8F,
	0x1A, 0xFB, 0xC6, 0x55, 0xA8, 0xC9, 0xA0, 0x13,
};

extern void PrintHex(unsigned char *buf, unsigned int size, int shift);

void main()
{
	unsigned char master_key[256];

	PrfGenerateBlock_v1_0(master_key, 256, pre_master_secret, sizeof(pre_master_secret), "PRF Testvector", test_seed, sizeof(test_seed));

	PrintHex(master_key, sizeof(master_key), 0);

	for(unsigned int i = 0; i < sizeof(verify_master_secret); ++i)
		master_key[i] -= verify_master_secret[i];

	PrintHex(master_key, sizeof(master_key), 0);

}
#endif