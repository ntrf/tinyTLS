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
#include <string.h>

#include "tinytls.h"

#include "MSocket.h"

#ifndef WIN32
# include <unistd.h>
# define pause(X) sleep(X)
#else
# include <Windows.h>
# define pause(X) Sleep((X) * 1000)
#endif


#if 1

#define TESTHOST "www.google.com"

//const char * hostname = "localhost";
//const char * hostname = "www.example.com";
//const char * hostname = "www.google.com";
//const char * hostname = "github.com";
//const char * hostname = "www.microsoft.com";
const char * hostname = TESTHOST;

const char * request =
"GET /notfound.html HTTP/1.1\r\n"
"Host: " TESTHOST "\r\n"
"Accept: */*\r\n"
"Connection: close\r\n"
"\r\n";

TinyTLSCertificateStorage * certdb = NULL;

int LoadCADB()
{
	FILE * f = NULL;

#if _MSC_VER > 1600
	errno_t e = fopen_s(&f, "calist.db", "rb");
	if (e != 0 || f == NULL) {
		fprintf(stderr, "Can't load CA databse!");
		return -1;
	}
#else
	f = fopen("calist.db", "rb");
	if (!f) {
		fprintf(stderr, "Can't load CA databse!");
		return -1;
	}
#endif

	fseek(f, 0, SEEK_END);
	size_t cadb_size = ftell(f);
	fseek(f, 0, SEEK_SET);

	uint8_t * cadb = new uint8_t[cadb_size];
	if (fread(cadb, 1, cadb_size, f) != cadb_size) {
		delete[] cadb;
		fclose(f);
		return -1;
	}

	fclose(f);

	certdb = ttlsCreateCertStorage(cadb, cadb_size);

	delete[] cadb;

	return (certdb != NULL) ? 1 : 0;
}

//-------------------------------------------------------------------

static int RecvFunction(void * ctx, uint8_t * data, size_t size)
{
	MSocket * ws = (MSocket*)ctx;
	int res = ws->recv((uint8_t *)data, size);
	return res;
}

static int SendFunction(void * ctx, const uint8_t * data, size_t size)
{
	MSocket * ws = (MSocket*)ctx;
	int res = ws->send(data, size);
	return res;
}

static int FlushFunction(void * context)
{
	return 0;
}

//-------------------------------------------------------------------

int make_request(MSocket & ws, TinyTLSContext * ctx, TTlsLink * link)
{
	ttlsReset(ctx);

	int res = ws.connect(hostname, 443);

	printf("Connect returned %d\n", res);
	if (res != 0) {
		return -1;
	}

	ttlsSetLink(ctx, link);

	do {
		int result = ttlsHandshake(ctx);
		if (result > 0) break;
		if (result < 0) {
			printf("Handshake failed with error %d\n", result);
			return -1;
		}
	} while (true);

	printf("\nREQUEST:\n==================\n%s", request);
	ttlsSend(ctx, (const uint8_t*)request, strlen(request));

	printf("\nRESPONSE:\n==================\n");

	for (;;) {
		uint8_t buf[60];
		int res = ttlsRecv(ctx, buf, 60);

		if (res <= 0) {
			printf("\n\n::res = %d\n", res);
			break;
		}

		fwrite(buf, 1, res, stdout);
	}

	ws.disconnect();
	return 0;
}

int main()
{
	MSocket ws;

	if (LoadCADB() <= 0)
		return -1;

	TTlsLink link;
	link.context = &ws;
	link.flush = &FlushFunction; // do nothing
	link.read_limit = 1024;
	link.write_limit = 1024;
	link.recv = &RecvFunction;
	link.send = &SendFunction;

	TinyTLSContext * ctx = ttlsCreateContext();

	ttlsSetHostname(ctx, hostname);
	ttlsUseCertStorage(ctx, certdb);

	int res1 = make_request(ws, ctx, &link);
	printf("Connection 1 result: %d\n", res1);
	pause(2);
	int res2 = make_request(ws, ctx, &link);
	printf("Connection 2 result: %d\n", res2);

	return 0;
}

#endif
