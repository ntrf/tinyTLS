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

#ifndef TINYTLS_AES_HMAC_SHA_H_
#define TINYTLS_AES_HMAC_SHA_H_

#include "aes/rijndael.h"

struct AES128_HMAC_SHA
{
	HMACSHA1_State mac_state;

	uint32_t IV[4]; //AES IV (or last cypertext)
	uint32_t key[4]; //AES key

	uint32_t rk[AES_RKLENGTH(128)]; //AES round keys (one time setup)

	// return minimum space required for encrypted packet

	uint32_t seq_num_low;
	uint32_t seq_num_high;

	AES128_HMAC_SHA();

	void InitEnc(uint8_t * aeskey, uint8_t * aesIV, uint8_t * hmackey);
	int32_t WrapPacket(Binary & output, uint8_t * header, const uint8_t * data, unsigned length);

	void InitDec(uint8_t * aeskey, uint8_t * aesIV, uint8_t * hmackey);
	int32_t UnWrapPacket(Binary & output, const uint8_t * header, const uint8_t * data, unsigned length);
};


#endif