/*
Magnetix project

Copyright 2010 Nesterov A.

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

#include <stdint.h>
#include <stdio.h>

#include <time.h>

#if defined(WIN32)
// ### might not work with Windows 8 apps / Windows Phone 8.1 apps
#  include <winsock2.h>
#  include <Ws2tcpip.h>
#else
#  include <unistd.h>
#  include <arpa/inet.h>
#  include <netdb.h>
#  include <errno.h>
#endif

#include "MSocket.h"

#if defined(WIN32)
// some really ugly stuff!
struct WSAInit
{
	WSAData wsaData;

	WSAInit()
	{
		WSAStartup(MAKEWORD(2, 0), &wsaData);
	}
	~WSAInit()
	{
		WSACleanup();
	}
} _WSAInit;

static int LastError()
{
	return WSAGetLastError();
}

#else
#  define INVALID_SOCKET -1
#  define closesocket(x) ::close(x)
typedef int SOCKET;

static int LastError()
{
	return errno;
}

#endif


MSocket::MSocket() : s(INVALID_SOCKET) {}

void MSocket::close() {
	if(s != INVALID_SOCKET) {
		closesocket((SOCKET)s);
		s = INVALID_SOCKET;
	}
}

int MSocket::connect(const char * host, uint32_t port)
{
	hostent * he = gethostbyname(host);

	if(!he)
		return LastError();

	sockaddr_in addr;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	memcpy(&(addr.sin_addr), he->h_addr_list[0], sizeof(addr.sin_addr));

	return connect(&addr);
}

int MSocket::connect(sockaddr_in * addr)
{
	s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(s == INVALID_SOCKET)
		return LastError();

	int ret = ::connect((SOCKET)s, (sockaddr*)addr, sizeof(sockaddr_in));
	if(ret != 0)
		return LastError();

	return 0;
}

void MSocket::disconnect()
{
	shutdown((SOCKET)s, 2);
	close();
}

bool MSocket::isConnected()
{
	return (s != INVALID_SOCKET);
}

int MSocket::recv(uint8_t * buffer, uint32_t length)
{
	return ::recv((SOCKET)s, (char*)buffer, length, 0);
}
int MSocket::send(const uint8_t * buffer, uint32_t length)
{
	return ::send((SOCKET)s, (const char*)buffer, length, 0);
}

int MSocket::geterror()
{
	return LastError();
}

