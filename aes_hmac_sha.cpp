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

#include <stdint.h>
#include <string.h>

#include "intutils.h"
#include "aes/rijndael.h"

#include "hash/hash.h"
#include "mlib/binary.h"

#include "aes_hmac_sha.h"

using namespace TinyTLS;

AES128_HMAC_SHA::AES128_HMAC_SHA()
	: seq_num_low(0), seq_num_high(0)
{
}

void AES128_HMAC_SHA::InitEnc(uint8_t * aeskey, uint8_t * aesIV, uint8_t * hmackey)
{
	memcpy(IV, aesIV, sizeof(IV));
	memcpy(key, aeskey, sizeof(key));

	uint32_t mac_key[16];
	memset(mac_key, 0, sizeof(mac_key));
	memcpy(mac_key, hmackey, 20);

	HmacSha1_Init(&mac_state, mac_key);

	rijndaelSetupEncrypt(rk, key, 128);

	seq_num_low = 0;
	seq_num_high = 0;
}

void AES128_HMAC_SHA::InitDec(uint8_t * aeskey, uint8_t * aesIV, uint8_t * hmackey)
{
	memcpy(IV, aesIV, sizeof(IV));
	memcpy(key, aeskey, sizeof(key));

	uint32_t mac_key[16];
	memset(mac_key, 0, sizeof(mac_key));
	memcpy(mac_key, hmackey, 20);

	HmacSha1_Init(&mac_state, mac_key);

	rijndaelSetupDecrypt(rk, key, 128);

	seq_num_low = 0;
	seq_num_high = 0;
}

static unsigned ExpandData(unsigned len)
{
	unsigned d = len + 20 + 1; //length + MAC + padding
	d = (d + 0xf) & (~0xf);
	return d;
}

static void cbc_encrypt(uint32_t * rk, uint32_t * IV, uint32_t * src, uint32_t * dest)
{
	uint32_t ysrc[4];
	ysrc[0] = IV[0] ^ src[0];
	ysrc[1] = IV[1] ^ src[1];
	ysrc[2] = IV[2] ^ src[2];
	ysrc[3] = IV[3] ^ src[3];
	rijndaelEncrypt(rk, AES_NROUNDS(128), (uint8_t*)ysrc, (uint8_t*)dest);
	IV[0] = dest[0];
	IV[1] = dest[1];
	IV[2] = dest[2];
	IV[3] = dest[3];
}

static void cbc_decrypt(uint32_t * rk, uint32_t * IV, uint32_t * src, uint32_t * dest)
{
	uint32_t ydest[4];
	rijndaelDecrypt(rk, AES_NROUNDS(128), (uint8_t*)src, (uint8_t*)ydest);
	dest[0] = IV[0] ^ ydest[0];
	dest[1] = IV[1] ^ ydest[1];
	dest[2] = IV[2] ^ ydest[2];
	dest[3] = IV[3] ^ ydest[3];
	IV[0] = src[0];
	IV[1] = src[1];
	IV[2] = src[2];
	IV[3] = src[3];
}

int32_t AES128_HMAC_SHA::WrapPacket(Binary & output, uint8_t * header, const uint8_t * data, unsigned length)
{
	unsigned outlen = ExpandData(length);
	if (output.length < outlen)
		output.alloc(outlen);

	uint8_t padlen = outlen - (length + 20 + 1); // padding length

	uint32_t mac[5];

	//use space for header - we don't need it otherwise yet
	mac[0] = bswap32(seq_num_high);
	mac[1] = bswap32(seq_num_low);

	*(uint16_t*)(header + 3) = bswap16(length);

	HMACSHA1_State s;
	HmacSha1_Reset(&s, &mac_state);

	HmacSha1_Update(&s, (const uint8_t*)mac, sizeof(uint64_t));
	HmacSha1_Update(&s, (const uint8_t*)header, 5);

	HmacSha1_Update(&s, data, length);
	HmacSha1_Finish(&s, mac);

	*(uint16_t*)(header + 3) = bswap16(outlen);

	//invoke AES (with CBC)

	// it's made so much easier in SSL 2:
	//  [MAC:20] <- fixed length
	//  [data :L]
	//  [padding :N-L]  <- minimal
	// 
	// but in TLS they decided that MAC should follow
	// data and padding is not required to be minimal.
	// eventualy this made Lucky13 attack possible.
	const uint8_t * src = data;
	uint32_t * dest = (uint32_t*)output.data;
	unsigned mac_offset = 0;
	unsigned i = 0, l = length;
	for (; i < outlen; i += 16) //one AES block at the time
	{
		// only plain text in this block
		if (!l) break;
		if (l >= 16) {
			cbc_encrypt(rk, IV, (uint32_t*)src, dest);
			src += 16;
			dest += 4;

			l -= 16;
		} else if (l > 0) { //plaintext + mac
			uint8_t src1[16];
			memcpy(src1, src, l);
			memcpy(src1 + l, (uint8_t*)mac, 16 - l);
			mac_offset = 16 - l;

			cbc_encrypt(rk, IV, (uint32_t*)src1, dest);
			dest += 4;
			l = 0;
		}
	}

	l = sizeof(mac)-mac_offset; //how much mac left to copy

	for (; i < outlen; i += 16) //one AES block at the time
	{
		if (!l) break;
		if (l >= 16) {
			cbc_encrypt(rk, IV, (uint32_t*)((uint8_t*)mac + mac_offset), dest);
			dest += 4;
			mac_offset += 16;
			l -= 16;
		} else {
			uint8_t src1[16];
			memcpy(src1, (uint8_t*)mac + mac_offset, l);
			memset(src1 + l, padlen, 16 - l); //fill the rest with padding length

			cbc_encrypt(rk, IV, (uint32_t*)src1, dest);
			dest += 4;
			l = 0;
		}
	}

	{
		uint8_t pad[16];
		memset(pad, padlen, 16 - l);
		for (; i < outlen; i += 16) //one AES block at the time
		{
			cbc_encrypt(rk, IV, (uint32_t*)pad, dest);
			dest += 4;
		}
	}

	seq_num_low += 1;
	if (seq_num_low == 0) seq_num_high += 1;

	return (int32_t)outlen;
}

int32_t AES128_HMAC_SHA::UnWrapPacket(Binary & output, const uint8_t * header, const uint8_t * data, unsigned length)
{
	if (output.length < length) {
		output.alloc(length);
	}

	// verify block alignment
	if ((length & (16 - 1)) != 0) {
		return -1;
	}


	uint32_t * from = (uint32_t*)data;
	uint32_t * to = (uint32_t*)output.data;

	for (uint32_t i = length; i > 0; i -= 16) {
		cbc_decrypt(rk, IV, from, to);
		from += 4;
		to += 4;
	}

	uint8_t padlen = output.data[length - 1];

	// verify enough space for mac
	size_t datasz = length - (padlen + 1 + 20); //20 = maclen

	size_t ver = 0;
	//### make constant - time!
	if (datasz >= length) {
		datasz = 0; ver = 1;
	}

	uint32_t mac[5];
	mac[0] = bswap32(seq_num_high);
	mac[1] = bswap32(seq_num_low);
	mac[2] = *(uint32_t *)header;
	*(uint16_t *)((uint8_t *)mac + 11) = bswap16(datasz);

	HMACSHA1_State s;
	HmacSha1_Reset(&s, &mac_state);

	HmacSha1_Update(&s, (const uint8_t*)mac, 13);

	HmacSha1_Update(&s, output.data, datasz);
	HmacSha1_Finish(&s, mac);

	uint32_t * inmac = (uint32_t *)((uint8_t*)output.data + datasz);

	// verify mac
	ver |= (mac[0] ^ inmac[0]) | (mac[1] ^ inmac[1]) | (mac[2] ^ inmac[2]) | (mac[3] ^ inmac[3]) | (mac[4] ^ inmac[4]);

	if (ver != 0)
		return -1;

	//### verify padding

	seq_num_low += 1;
	if (seq_num_low == 0) seq_num_high += 1;

	return (int)datasz;
}

#if 0

// Gathered with wireshark between Nginx and Firefox

uint8_t key_seed[] = {
	0x53, 0x81, 0xc7, 0x52, 0xd9, 0x3c, 0xbe, 0xe6,
	0x10, 0xb7, 0x6c, 0xc2, 0xa9, 0xb7, 0x77, 0x45,
	0xa6, 0x57, 0xb4, 0x8a, 0xfb, 0x24, 0x5d, 0xdb,
	0x11, 0xc1, 0xf8, 0xaf, 0x72, 0xed, 0x99, 0x70,
	0xa3, 0x2e, 0x2a, 0x09, 0x1e, 0x6f, 0x38, 0x62,
	0xec, 0x53, 0x4e, 0x7f, 0xd2, 0xd2, 0x59, 0xab,
	0xcd, 0x93, 0x67, 0x9a, 0x93, 0x1c, 0x51, 0x98,
	0x83, 0xc1, 0xb0, 0xd0, 0xe5, 0x1d, 0xf1, 0xe0
};

uint8_t master_secret[] = {
	0xfd, 0x00, 0xb1, 0x26, 0xb8, 0x0c, 0xfb, 0xe8,
	0x61, 0x9f, 0x40, 0x2f, 0x4d, 0x2e, 0xd8, 0x0d,
	0x54, 0xd0, 0xcc, 0xef, 0x50, 0x85, 0x23, 0xcd,

	0x5f, 0x43, 0x23, 0x16, 0x8f, 0xa5, 0x74, 0xda,
	0x8f, 0x45, 0x42, 0x63, 0xd2, 0x46, 0x9f, 0x10,
	0xfa, 0x8b, 0x6f, 0x6b, 0x39, 0xf0, 0xc1, 0x59
};

uint8_t verifyKeys[] = {
	0xfd, 0xf9, 0x8c, 0xe8, 0x84, 0xb2, 0xd5, 0xf3,
	0xd2, 0x4f, 0x23, 0x5c, 0xf6, 0xb0, 0x39, 0xc1,
	0xe2, 0xf0, 0xdd, 0x5e, 0x30, 0x5e, 0x13, 0xe9,
	0x75, 0x3b, 0x6d, 0x26, 0x0e, 0xe4, 0xfb, 0x47,
	0xe3, 0x99, 0xc7, 0x8b, 0x56, 0x56, 0xdb, 0x97,
	0xa8, 0x58, 0x3f, 0x24, 0x5f, 0x84, 0x17, 0xc1,
	0x16, 0x5f, 0xc5, 0xd8, 0x64, 0x4d, 0xcd, 0x62,
	0x8f, 0x84, 0xaf, 0x7d, 0xd4, 0x1d, 0x1a, 0xed,
	0xc0, 0x9b, 0x22, 0x38, 0xae, 0x74, 0x52, 0x18,
	0x59, 0x08, 0x9d, 0x49, 0xf7, 0xea, 0xc9, 0xa8,
	0x14, 0xdf, 0x26, 0x99, 0xbd, 0x05, 0xf9, 0x18,
	0xda, 0x85, 0xdc, 0x06, 0x55, 0xa4, 0x05, 0x80,
	0x8d, 0x97, 0x6c, 0x2b, 0x2c, 0x76, 0xfc, 0x59,
};

uint8_t plaintext[] = {
	0x14, 0x00, 0x00, 0x0c, 0xe6, 0x0e, 0x16, 0xcf, 0x87, 0x78, 0x89, 0x79, 0x28, 0x73, 0x25, 0xe5,
	0x40, 0x5d, 0xaa, 0xa3, 0xa9, 0x45, 0xce, 0xc4, 0x40, 0xee, 0x25, 0x4a, 0x1d, 0x89, 0xd5, 0x44,
	0xf4, 0xcc, 0x9d, 0x75, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
};

uint8_t MacHead[] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0x16, 0x03, 0x01, 0x00, 0x10
};

uint8_t cyphertext[] = {
	0x35, 0xde, 0x87, 0x69, 0xc4, 0x17, 0x58, 0x0a, 0xe6, 0x44, 0x88, 0x47, 0x74, 0x01, 0xd1, 0x14,
	0xfe, 0x18, 0x43, 0xdf, 0xc8, 0x2a, 0x25, 0x95, 0x12, 0xa2, 0x99, 0xfc, 0x28, 0xf1, 0x40, 0x5d,
	0xf7, 0x40, 0xdd, 0x83, 0xf6, 0x26, 0xd5, 0xf5, 0x8b, 0x4c, 0xa8, 0xba, 0x8c, 0xdb, 0x9c, 0x96
};

void main()
{
	Binary key_block;

	key_block.alloc(20 * 2 + 16 * 2 + 16 * 2);
	PrfGenerateBlock_v1_0(key_block.data, key_block.length, master_secret, 48, "key expansion", key_seed, 64);

	uint8_t * client_MAC_secret = key_block.data + 0;
	uint8_t * client_key = key_block.data + 40;
	uint8_t * client_IV = key_block.data + 40 + 32;

	AES128_HMAC_SHA active_encryption;



	active_encryption.Init(client_key, client_IV, client_MAC_secret);

	Binary out;
	active_encryption.WrapPacket(out, TestClientFinishedPacket, plaintext, 16);

	for (unsigned i = 0; i < 48; ++i) {
		out.data[i] -= cyphertext[i];
	}
	PrintHex(out.data, out.length, 0);
}
#endif