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

/* INTERNAL.H
 * Context of TinyTLS
 * Each context contains everything required for a single connection
 */

#ifndef TINYTLS_INTERNAL_H_
#define TINYTLS_INTERNAL_H_

#include "tinytls.h"

#include <stdint.h>

#include "pkcs1/bigint.h"
#include "mlib/charstr.h"

#define TINYTLS_MAX_CERT_CHAIN_LENGTH 100

#pragma pack(push, 1)
struct TlsHead
{
	uint8_t type;
	uint8_t version_major;
	uint8_t version_minor;
	uint16_t length;
};
#pragma pack(pop)

struct TinyTLSContext;

struct TinyTLSRandomNumberGeneratorInterface
{
	/// Theese functions are reserved for COM or other pre-defined interfaces
	virtual void reserved0() {};
	virtual void reserved1() {};
	virtual void reserved2() {};
	virtual void reserved3() {};

	virtual int GenerateRandomBytes(TinyTLSContext * ctx, uint8_t * data, int length) = 0;
	virtual void Shutdown(TinyTLSContext * ctx) = 0;
};

struct TinyTLSCertificateStorage
{
	virtual ~TinyTLSCertificateStorage() { }
	virtual int AskCertificate(const uint8_t * issuer, uint32_t issuerLen, const uint8_t ** certificate, uint32_t * certificateLen) = 0;
};

struct TinyTLSContext
{
	/// Random number generator context
	TinyTLSRandomNumberGeneratorInterface * rng_ctx;

	/// Montgomery reduction context
	/// Used by RSA and DH
	MontgomeryReductionContext mr_ctx;

	/// Certificate storage
	TinyTLSCertificateStorage * certificate_strogate;

	/// Assigned host name
	charstr HostName;
};

extern int ttlsInitSystemRandomGenerator(TinyTLSContext * ctx);

extern TinyTLSContext * ttlsCreateContext();

#ifndef NDEBUG
extern const char * hexBlock(const uint8_t * value, int len);
extern void writeKeyLogClientRandom(const uint8_t * random, const uint8_t * master);
extern void PrintHex(const unsigned char *buf, unsigned int size, int shift);
extern void PrintOct(const unsigned char *buf, unsigned int size, int shift);
#endif

#endif