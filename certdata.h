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

#ifndef CERTDATA_H_
#define CERTDATA_H_

#include "mlib/binary.h"
#include "pkcs1/pkcs1.h"

/* Certificate usage */
enum
{
	CERTUSAGE_KEY_AGREEMENT = (1 << 0),
	CERTUSAGE_KEY_ENCRYPTION = (1 << 1),
	CERTUSAGE_DATA_ENCRYPTION = (1 << 2),
	CERTUSAGE_CA = (1 << 16),

	CERT_DOMAIN_MATCH = (1 << 18),
};


struct CertificateInfo{
	int keyType;
	int signType;

	Binary publicKey;
	Binary signature;

	Binary issuer;
	Binary subject;

	uint32_t restricted;
	int32_t chainLength;

	uint32_t payloadOffset;
	uint32_t payloadLength;
};

//extract public key form X.509 certificate
int ExtractCertificateInfo(CertificateInfo * out, int length, const uint8_t * source, const char * hostname = NULL);
int Extract_PKCS1_RSA_PublicKeyComponents(PKCS1_RSA_PublicKey * out, int length, const uint8_t * source);
int Extract_PKCS1_RSA_PrivateKeyComponents(PKCS1_RSA_PrivateKey * out, int length, const uint8_t * source);

struct CertifacteBinary
{
	size_t length;
	const uint8_t * data;
};

int VerifyCertificateChain(TinyTLSContext * ctx, const CertifacteBinary * certs, CertificateInfo * cert_storage, size_t count);

#endif