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

/* PKCS1.H
 * Header file for RSA cryptosystem (PKCS #1)
 */

#ifndef TINYTLS_PKCS1_H_
#define TINYTLS_PKCS1_H_

#include "../mlib/binary.h"

struct BinarySlice
{
	size_t length;
	const uint8_t * data;
};

/* Signature type */
enum
{
	SIGTYPE_UNKNOWN = 0,

	PKCS1_RSAES,

	// special value for TLS 1.0 client certificate verify
	// payload is not prefixed with algorithm identifier
	// and is exactly 36 bytes
	PKCS1_SSA_TLSVERIFY,

	PKCS1_SSA_MD5,

	PKCS1_SSA_SHA1,
	PKCS1_SSA_SHA256,
	PKCS1_SSA_SHA384,
	PKCS1_SSA_SHA512,

	// the first trusted signature type
	// everything bellow will fail to validate
	PKCS1_SSA_TRUSTED = PKCS1_SSA_SHA1
};

struct PKCS1_RSA_PublicKey{
	TinyTLS::Binary exponent;
	TinyTLS::Binary modulus;
};

// Simplified private key. More efficient CRT-key can be extracted instead.
struct PKCS1_RSA_PrivateKey
{
	TinyTLS::Binary priv_exp;
	TinyTLS::Binary pub_exp;
	TinyTLS::Binary modulus;
};

void EncryptRSA(struct TinyTLSContext * ctx, TinyTLS::Binary & out, unsigned int size, const PKCS1_RSA_PublicKey & Key, const uint8_t * data, unsigned length);

int GetRSAAlgorithmType(const uint8_t * oid, uint32_t length);
int ComputeRSASignatureHash(int sigtype, const uint8_t * data, unsigned length, uint32_t * hash);
int VerifyRSASignatureHash(struct MontgomeryReductionContext * ctx, const TinyTLS::Binary & signature, unsigned int size, const PKCS1_RSA_PublicKey & Key, int sigtype, const uint32_t * hash);
int VerifyRSASignature(struct MontgomeryReductionContext * ctx, const TinyTLS::Binary & signature, unsigned int size, const PKCS1_RSA_PublicKey & Key, int sigtype, const uint8_t * data, unsigned length);

int GenerateRSASignatureHash(struct MontgomeryReductionContext * ctx, TinyTLS::Binary & signature, unsigned int size, const PKCS1_RSA_PrivateKey & Key, int sigtype, const uint32_t * hash);
int GenerateRSASignature(struct MontgomeryReductionContext * ctx, TinyTLS::Binary & signature, unsigned int size, const PKCS1_RSA_PrivateKey & Key, int sigtype, const uint8_t * data, unsigned length);

#endif