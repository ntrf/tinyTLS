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

#ifndef MSOCKET_H_
#define MSOCKET_H_

struct MSocket
{
	unsigned int s;

	MSocket();
	void close();

	int connect(const char * host, unsigned port);
	int connect(struct sockaddr_in * addr);
	void disconnect();

	bool isConnected();

	int recv(uint8_t * buffer, uint32_t length);
	int send(const uint8_t * buffer, uint32_t length);

	int geterror();
};

#endif