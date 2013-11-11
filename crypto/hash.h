/*
   tinyTLS project

   Copyright 2013 Nesterov A.

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
#ifndef TINYTLS_HASH_H_
#define TINYTLS_HASH_H_

#include <stdint.h>

// MD5 implementation

struct MD5_State
{
	uint32_t md5state[4];
	uint8_t buf[128];
	uint32_t buf_len;
	uint32_t full_len;
};

void md5Init(MD5_State * state);
void md5Update(MD5_State * state, const uint8_t * input, uint32_t length);
void md5Finish(MD5_State * state, uint32_t result[4]);

// HMAC with MD5
void HmacMd5(uint32_t result[4],const uint32_t key[16], const uint8_t * data, uint32_t length);


// HMAC with MD5 for long messages

struct HMACMD5_State
{
	MD5_State md5State;
	uint32_t key[16];
};

void HmacMd5_Init(HMACMD5_State * state, const uint32_t key[16]);
void HmacMd5_Update(HMACMD5_State * state, const uint8_t * data, uint32_t length);
void HmacMd5_Finish(HMACMD5_State * state, uint32_t result[4]);

#endif