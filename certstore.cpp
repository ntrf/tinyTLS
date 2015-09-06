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

#include <stdio.h>

#include "cdb/cdb.h"
#include "internal.h"

#include "pkcs1/pkcs1.h"

namespace tinyTLS
{

	class CertificateStorage_CDB : public TinyTLSCertificateStorage
	{
		cdb db;
		Binary contents;
	public:
		CertificateStorage_CDB();
		~CertificateStorage_CDB();
		int AskCertificate(const uint8_t * issuer, uint32_t issuerLen, const uint8_t ** certificate, uint32_t * certificateLen);

		int Load(const uint8_t * data, size_t size);
	};

	CertificateStorage_CDB::CertificateStorage_CDB()
	{
		memset(&db, 0, sizeof(db));
	}

	int CertificateStorage_CDB::Load(const uint8_t * data, size_t size)
	{
		contents.alloc(size);
		memcpy(contents.data, data, size);

		cdb_init(&db, contents.data, contents.length);
		return 1;
	}

	CertificateStorage_CDB::~CertificateStorage_CDB()
	{
		cdb_free(&db);
		contents.clear();
	}

	int CertificateStorage_CDB::AskCertificate(const uint8_t * issuer, uint32_t issuerLen, const uint8_t ** certificate, uint32_t * certificateLen)
	{
		int res = cdb_find(&db, issuer, (size_t)issuerLen);

		// if nothing found - return as unknown
		if (res <= 0) return 0;

		size_t datalen = cdb_datalen(&db);
		// if length is zero - certificate in untrusted
		if (datalen == 0)
			return -1;

		// found certificate in store
		// retrieve it for signature check
		*certificate = (contents.data + cdb_datapos(&db));
		*certificateLen = (uint32_t)datalen;
		return 1;
	}
}

extern "C"
{
	/// Create certificate storage and load contents from memory
	struct TinyTLSCertificateStorage * ttlsCreateCertStorage(const uint8_t * mem, size_t size)
	{
		tinyTLS::CertificateStorage_CDB * cs = new tinyTLS::CertificateStorage_CDB();
		if (cs->Load(mem, size) <= 0) {
			delete cs;
			return NULL;
		}
		return cs;
	}

	/// Destroy certificate storage
	void ttlsFreeCertStorage(struct TinyTLSCertificateStorage * cs)
	{
		delete cs;
	}
}