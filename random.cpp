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
#include <stdint.h>
#include <stdlib.h>

#include "internal.h"

#if defined(WIN32)

#pragma comment(lib, "advapi32.lib")
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>

class SystemRandomNumberGenerator : public TinyTLSRandomNumberGeneratorInterface
{
	HCRYPTPROV provider;
public:
	int Init(TinyTLSContext * ctx)
	{
		if (!::CryptAcquireContext(&provider, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
			//### FALLBACK ???
			fprintf(stderr, "Failed to acquire context: %08x\n", GetLastError());
			return -1;
		}
		return 1;
	}

	void Shutdown(TinyTLSContext * ctx)
	{
		::CryptReleaseContext(provider, 0);
		delete this;
	}

	int GenerateRandomBytes(TinyTLSContext * ctx, uint8_t * data, int length)
	{
		if (!::CryptGenRandom(provider, (DWORD)length, (BYTE*)data)) {
			return -1;
		}
		return length;
	}
};

#elif defined(__APPLE__) || defined(APPLE)
#include <Security/Security.h>

class SystemRandomNumberGenerator : public TinyTLSRandomNumberGeneratorInterface
{
public:
	void Init(TinyTLSContext * ctx) { return 1; }

	void Shutdown(TinyTLSContext * ctx) { delete this; }

	int GenerateRandomBytes(TinyTLSContext * ctx, uint8_t * data, int length)
	{
		if (::SecRandomCopyBytes(kSecRandomDefault, length, data) != 0) {
			return -1;
		}
		return length;
	}
};

#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

class SystemRandomNumberGenerator : public TinyTLSRandomNumberGeneratorInterface
{
	int fd;
public:
	int Init(TinyTLSContext * ctx)
	{
		fd = open("/dev/urandom", O_RDONLY);
		return fd;
	}

	void Shutdown(TinyTLSContext * ctx)
	{
		close(fd);
		delete this;
	}

	int GenerateRandomBytes(TinyTLSContext * ctx, uint8_t * data, int length)
	{
		return read(fd, data, length);
	}
};
#endif

int ttlsInitSystemRandomGenerator(TinyTLSContext * ctx)
{
	SystemRandomNumberGenerator * rng = new SystemRandomNumberGenerator;
	if (rng->Init(ctx) < 0) {
		return -1;
	}
	
	if (ctx->rng_ctx != NULL) {
		ctx->rng_ctx->Shutdown(ctx);
		ctx->rng_ctx = NULL;
	}

	ctx->rng_ctx = rng;
	return 0;
}
