/*
tinyTLS project

Copyright 2014 Nesterov A.

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

/* PKCS1.CPP
 * Cryptographic primitives for RSA cryptosystem (PKCS #1)
 *  - RSAES-PKCS1-v1_5 encryption
 *  - RSASSA-PKCS1-v1_5 signature verification
 * Notice: current implementation only supports exponents no larger
 * than 2^{32} - 1
 */

//#define TEST_MODULE

#include <string.h>
#include <stdint.h>

#include "../mlib/binary.h"

#include "internal.h"

/* Encryption */

void EncryptRSA(TinyTLSContext * ctx, Binary & out, unsigned int size, const Binary & Modulus, const Binary & Exponent, const uint8_t * data, unsigned length)
{
	out.alloc(size);

	unsigned char * buf = out.begin();

	unsigned int seedsize = size - 3 - length;

	buf[0] = 0;
	buf[1] = 2;

	ctx->rgn_ctx->GenerateRandomBytes(ctx, buf + 2, seedsize);
	for (unsigned int x = 0; x < seedsize; ++x) {
		if (buf[2 + x] == 0) buf[2 + x] = 0xFF;
	}

	buf[2 + seedsize] = 0;
	memcpy(buf+3+seedsize, data, length);

	{
		unsigned exponent = 0;

		if (Exponent.length <= sizeof(unsigned)) { // BAD
			unsigned l = 0;
			for (; l < Exponent.length; ++l) {
				exponent = (exponent << 8) + Exponent.data[l];
			}
		}

		ctx->mr_ctx.Prepare(Modulus.data, Modulus.length, size / 4, true);
		ctx->mr_ctx.ExpMod_Fnum((uint32_t *)out.data, (const uint32_t *)buf, exponent, true);
	}
}

/* Signature verification */

#include "hash.h"

#define OID_2B(x) (0x80 | ((X) >> 7)), (x & 127)
#define OID_3B(x) (0x80 | ((X) >> 14)), (0x80 | ((X) >> 7) & 127), (x & 127)

#define ASN_NULL 0x05, 0x00
#define ASN_SEQUENCE(L) 0x30, (L)
#define ASN_OID(L) 0x06, (L)
#define ASN_OCTETSTRING(L) 0x04, (L)


static const uint8_t pkcs1[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 1, 1};

static const uint8_t rsaMd5DigestInfo[34-16] = {
	ASN_SEQUENCE(32), 
	ASN_SEQUENCE(12), 
	ASN_OID(8), 
	(40 + 2), 0x86, 0x48, 0x86, 0xF7, 0x0D, 2, 5, 
	ASN_NULL,
	ASN_OCTETSTRING(16)
};
static const uint8_t rsaSha1DigestInfo[35 - 20] = {
	ASN_SEQUENCE(33), 
	ASN_SEQUENCE(9), 
	ASN_OID(5), 
	(40 + 3), 14, 3, 2, 26, 
	ASN_NULL,
	ASN_OCTETSTRING(20)
};
static const uint8_t rsaSha256DigestInfo[51 - 32] = {
	ASN_SEQUENCE(49),
	ASN_SEQUENCE(13), 
	ASN_OID(9), 
	(80 + 16), 0x86, 0x48, 1, 101, 3, 4, 2, 1, 
	ASN_NULL,
	ASN_OCTETSTRING(32)
};

#include "pkcs1.h"

int GetRSAAlgorithmType(const uint8_t * oid, uint32_t length)
{
	if ((length == sizeof(pkcs1)+1) && (memcmp(oid, pkcs1, sizeof(pkcs1)) == 0)) {
		oid += sizeof(pkcs1);
		if (*oid == 1) { // Encryption
			return PKCS1_RSAES;
		}  else if (*oid == 4) { // MD5
			return PKCS1_SSA_MD5;
		} else if(*oid == 5) { // SHA1
			return PKCS1_SSA_SHA1;
		} else if(*oid == 11) { // SHA256
			return PKCS1_SSA_SHA256;
		}
	}
	return SIGTYPE_UNKNOWN;
}

int VerifyRSASignature(TinyTLSContext * ctx, const Binary & signature, unsigned int size, const Binary & Modulus, const Binary & Exponent, int sigtype, const uint8_t * data, unsigned length)
{
	unsigned N = 0;

	if (sigtype == PKCS1_SSA_MD5) {
		N = size - sizeof(rsaMd5DigestInfo)-16 - 1;
	} else if (sigtype == PKCS1_SSA_SHA1) {
		N = size - sizeof(rsaSha1DigestInfo)-20 - 1;
	} else if (sigtype == PKCS1_SSA_SHA256) {
		N = size - sizeof(rsaSha256DigestInfo)-32 - 1;
	} else {
		return -1;
	}

	//unsigned char * buf = new unsigned char[size];
	Binary buf;

	int valid = 0;
	{
		unsigned exponent = 0;

		if (Exponent.length <= sizeof(unsigned)) { // BAD
			unsigned l = 0;
			for (; l < Exponent.length; ++l) {
				exponent = (exponent << 8) + Exponent.data[l];
			}
		}

		buf.alloc(size);

		MontgomeryReductionContext mr_ctx;
		ctx->mr_ctx.Prepare(Modulus.data, Modulus.length, size / 4, true);
		ctx->mr_ctx.ExpMod_Fnum((uint32_t *)buf.data, (const uint32_t *)signature.data, exponent, true);
	}

	if (buf[0] != 0 || buf[1] != 1) {
		return 0;
	}

	// bytes 2 .. N-1 are full of FF
	// byte N == 0
	// bytes N+1 .. size-1 equal to prefix
	// notice: this design protects against timing attacks
	int y = 0xFF;
	for (unsigned i = 2; i < N; ++i) y &= buf[i];
	if (y != 0xFF) {
		return 0;
	}

	if (buf[N] != 0x00) {
		return 0;
	}

	++N;

	if (sigtype == PKCS1_SSA_MD5) {
		if (memcmp(buf.data + N, rsaMd5DigestInfo, sizeof(rsaMd5DigestInfo)) != 0) {
			return 0;
		}
		N += sizeof(rsaMd5DigestInfo);

		uint32_t hash[4];
		MD5_State state;

		//verify the signature hash
		md5Init(&state);
		md5Update(&state, data, length);
		md5Finish(&state, hash);

		valid = (memcmp(buf.data + N, hash, sizeof(hash)) == 0) ? 1 : 0;

	} else if (sigtype == PKCS1_SSA_SHA1) {
		if (memcmp(buf.data + N, rsaSha1DigestInfo, sizeof(rsaSha1DigestInfo)) != 0) {
			return 0;
		}
		N += sizeof(rsaSha1DigestInfo);


		uint32_t hash[5];
		SHA1_State state;

		//verify the signature hash
		sha1Init(&state);
		sha1Update(&state, data, length);
		sha1Finish(&state, hash);

		valid = (memcmp(buf.data + N, hash, sizeof(hash)) == 0) ? 1 : 0;
	} else if (sigtype == PKCS1_SSA_SHA256) {
		if (memcmp(buf.data + N, rsaSha256DigestInfo, sizeof(rsaSha256DigestInfo)) != 0) {
			return 0;
		}
		N += sizeof(rsaSha256DigestInfo);

		uint32_t hash[8];
		SHA256_State state;

		//verify the signature hash
		sha256Init(&state);
		sha256Update(&state, data, length);
		sha256Finish(&state, hash);
		
		valid = (memcmp(buf.data + N, hash, sizeof(hash)) == 0) ? 1 : 0;
	}

	return valid;
}


#if TEST_MODULE
#include <stdio.h>

unsigned char Modulus[] = {
	0xa8, 0xb3, 0xb2, 0x84, 0xaf, 0x8e, 0xb5, 0x0b, 0x38, 0x70, 0x34, 0xa8, 0x60, 0xf1, 0x46, 0xc4, 
	0x91, 0x9f, 0x31, 0x87, 0x63, 0xcd, 0x6c, 0x55, 0x98, 0xc8, 0xae, 0x48, 0x11, 0xa1, 0xe0, 0xab, 
	0xc4, 0xc7, 0xe0, 0xb0, 0x82, 0xd6, 0x93, 0xa5, 0xe7, 0xfc, 0xed, 0x67, 0x5c, 0xf4, 0x66, 0x85, 
	0x12, 0x77, 0x2c, 0x0c, 0xbc, 0x64, 0xa7, 0x42, 0xc6, 0xc6, 0x30, 0xf5, 0x33, 0xc8, 0xcc, 0x72, 
	0xf6, 0x2a, 0xe8, 0x33, 0xc4, 0x0b, 0xf2, 0x58, 0x42, 0xe9, 0x84, 0xbb, 0x78, 0xbd, 0xbf, 0x97, 
	0xc0, 0x10, 0x7d, 0x55, 0xbd, 0xb6, 0x62, 0xf5, 0xc4, 0xe0, 0xfa, 0xb9, 0x84, 0x5c, 0xb5, 0x14, 
	0x8e, 0xf7, 0x39, 0x2d, 0xd3, 0xaa, 0xff, 0x93, 0xae, 0x1e, 0x6b, 0x66, 0x7b, 0xb3, 0xd4, 0x24, 
	0x76, 0x16, 0xd4, 0xf5, 0xba, 0x10, 0xd4, 0xcf, 0xd2, 0x26, 0xde, 0x88, 0xd3, 0x9f, 0x16, 0xfb 
};

unsigned Exponent = 65537;

unsigned char Message[] = {
	0x75, 0x0c, 0x40, 0x47, 0xf5, 0x47, 0xe8, 0xe4, 0x14, 0x11, 0x85, 0x65, 0x23, 0x29, 0x8a, 0xc9, 
	0xba, 0xe2, 0x45, 0xef, 0xaf, 0x13, 0x97, 0xfb, 0xe5, 0x6f, 0x9d, 0xd5 
};

unsigned char Seed[] = {
	0xac, 0x47, 0x28, 0xa8, 0x42, 0x8c, 0x1e, 0x52, 0x24, 0x71, 0xa8, 0xdf, 0x73, 0x5a, 0x8e, 0x92,
	0x92, 0xaf, 0x0d, 0x55, 0xbc, 0xb7, 0x3a, 0x12, 0xac, 0x32, 0xc2, 0x64, 0xf3, 0x88, 0x1c, 0x7c,
	0x8a, 0x71, 0x0f, 0x70, 0xfe, 0xb1, 0x04, 0x85, 0xc8, 0x37, 0x0f, 0x78, 0x1f, 0xff, 0xd0, 0x21,
	0x81, 0x6f, 0x05, 0x87, 0x39, 0x76, 0x6d, 0xa0, 0xa9, 0xc9, 0xdb, 0x0e, 0xae, 0x7e, 0x9a, 0x25,
	0xb6, 0xc4, 0x33, 0x18, 0xd0, 0xca, 0xac, 0x23, 0x65, 0x22, 0xca, 0x31, 0x0f, 0x17, 0xfc, 0x52,
	0xad, 0x42, 0x29, 0xc8, 0x3a, 0x24, 0xe9, 0xe5, 0x45, 0xeb, 0x35, 0xe9, 0x82, 0x6d, 0x55, 0x9f,
	0x57
};

unsigned char Result[] = {
	0x68, 0x42, 0xe5, 0xe2, 0xcc, 0x00, 0x41, 0xd6, 0xb0, 0xc8, 0x1a, 0x56, 0x2c, 0x39, 0xa6, 0x17,
	0x37, 0x9a, 0x51, 0x5c, 0xab, 0x74, 0xab, 0xcb, 0x26, 0x19, 0xc7, 0x74, 0x0a, 0x54, 0x1d, 0x95,
	0x55, 0xdd, 0x91, 0x65, 0x97, 0x5b, 0xf8, 0xa3, 0xeb, 0xd0, 0xd0, 0x45, 0x66, 0x61, 0xdf, 0xb1,
	0xa6, 0x86, 0x1b, 0xa2, 0x33, 0x22, 0x69, 0x93, 0x0e, 0x0d, 0xb5, 0x14, 0xfc, 0xa0, 0x73, 0x3e,
	0xeb, 0x9c, 0x40, 0x57, 0x13, 0xeb, 0x1f, 0x9d, 0x76, 0x80, 0x33, 0xed, 0x29, 0x3e, 0x1e, 0x08,
	0x1a, 0x12, 0x5f, 0x32, 0xdd, 0xb9, 0xea, 0x52, 0xed, 0xbe, 0x27, 0x5c, 0x4a, 0xf6, 0x0f, 0x8a,
	0x7b, 0xf8, 0x32, 0xbd, 0x22, 0x75, 0x61, 0xc2, 0x08, 0xdc, 0x00, 0x31, 0xa8, 0x4b, 0x50, 0x12,
	0xc9, 0xdd, 0x9f, 0x74, 0x45, 0x9d, 0xcb, 0x07, 0x0b, 0xdb, 0xe1, 0x3c, 0xfa, 0x8c, 0x2d, 0x50,
};

extern void PrintHex(const unsigned char *buf, unsigned int size, int shift);

int main()
{
	unsigned char buf[128];

	buf[0] = 0;
	buf[1] = 2;
	memcpy(buf + 2, Seed, 128 - 3 - sizeof(Message));
	buf[128 - 1 - sizeof(Message)] = 0;
	memcpy(buf + 128 - sizeof(Message), Message, sizeof(Message));

	MontgomeryReductionContext mr_ctx;
	mr_ctx.Prepare(Modulus, 128, 128 / 4, true);
	mr_ctx.ExpMod_Fnum((uint32_t *)buf, (const uint32_t *)buf, Exponent, true);

	bool match = memcmp(buf, Result, 128) == 0;
	
	PrintHex(buf, 128, 0);
	printf("%s\n", match ? "Match" : "!!!! Mismatch  !!!!");

	return match ? 0 : -1;
}

#endif