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

/* TLS.CPP
* Transport Layer Security v1.0 main protocol implementation and 
* external API.
*/


#include <stdint.h>
#include <stdio.h>
#include <memory.h>

// Using standart library for time. Used in client_random during 
// handshake. Scince standard does not require this to be exact we 
// can just use libc implemenetation instead of OS implementation.
#include <time.h>

#include "internal.h"
#include "intutils.h"
#include "certdata.h"

#include "hash/hash.h"

#include "mlib/charstr.h"

typedef uint16_t CipherSuite;

#define MAKE_UINT16(A, B) ((A) + ((B) << 8))

	static const CipherSuite TLS_NULL_WITH_NULL_NULL                = MAKE_UINT16( 0x00,0x00 );

    static const CipherSuite TLS_RSA_WITH_NULL_SHA                  = MAKE_UINT16( 0x00,0x02 );

	static const CipherSuite TLS_RSA_WITH_AES_128_CBC_SHA           = MAKE_UINT16( 0x00, 0x2F );
	static const CipherSuite TLS_DH_DSS_WITH_AES_128_CBC_SHA        = MAKE_UINT16( 0x00, 0x30 );
	static const CipherSuite TLS_DH_RSA_WITH_AES_128_CBC_SHA        = MAKE_UINT16( 0x00, 0x31 );
	static const CipherSuite TLS_DHE_DSS_WITH_AES_128_CBC_SHA       = MAKE_UINT16( 0x00, 0x32 );
	static const CipherSuite TLS_DHE_RSA_WITH_AES_128_CBC_SHA       = MAKE_UINT16( 0x00, 0x33 );
	static const CipherSuite TLS_DH_anon_WITH_AES_128_CBC_SHA       = MAKE_UINT16( 0x00, 0x34 );

	static const CipherSuite TLS_RSA_WITH_AES_256_CBC_SHA           = MAKE_UINT16( 0x00, 0x35 );
	static const CipherSuite TLS_DH_DSS_WITH_AES_256_CBC_SHA        = MAKE_UINT16( 0x00, 0x36 );
	static const CipherSuite TLS_DH_RSA_WITH_AES_256_CBC_SHA        = MAKE_UINT16( 0x00, 0x37 );
	static const CipherSuite TLS_DHE_DSS_WITH_AES_256_CBC_SHA       = MAKE_UINT16( 0x00, 0x38 );
	static const CipherSuite TLS_DHE_RSA_WITH_AES_256_CBC_SHA       = MAKE_UINT16( 0x00, 0x39 );
	static const CipherSuite TLS_DH_anon_WITH_AES_256_CBC_SHA       = MAKE_UINT16( 0x00, 0x3A );

	// probably won't use it
	static const CipherSuite TLS_FALLBACK_SCSV                      = MAKE_UINT16( 0x56, 0x00 );
#undef MAKE_UINT16

namespace HandshakeType {
	enum {
		hello_request = 0,
		client_hello = 1,
		server_hello = 2,
		certificate = 11,
		server_key_exchange = 12,
		certificate_request = 13,
		server_hello_done = 14,
		certificate_verify = 15,
		client_key_exchange = 16,
		finished = 20
	};
};

namespace AlertType
{
	enum
	{
		close_notify = 0,
		unexpected_message = 10,
		bad_record_mac = 20,
		record_overflow = 22,
		decompression_failure = 30,
		handshake_failure = 40,
		bad_certificate = 42,
		unsupported_certificate = 43,
		certificate_revoked = 44,
		certificate_expired = 45,
		certificate_unknown = 46,
		illegal_parameter = 47,
		unknown_ca = 48,
		access_denied = 49,
		decode_error = 50,
		decrypt_error = 51,
		protocol_version = 70,
		insufficient_security = 71,
		internal_error = 80,
		user_canceled = 90,
		no_renegotiation = 100,
	};
}

static const size_t MAX_CERTS = 6;

//-------------------------------------------------------------------
// Some constant info with supported cyphersuites and fixed packets

#pragma pack(push, 1)

// Capabilities block inserted into the Client Hello Message
const uint8_t ClentHelloCaps[] = {
	0, 4, //cipher_suites
	0x00, 0x9C,
	0x00, 0x2F, // TLS_RSA_WITH_AES_128_CBC_SHA

	1, //compression_methods
	0
};

// ChangeCypherState packet
// Scince it's never going to change, we store it in constant memory
const uint8_t CCSPacket[] = {
	0x14,
	3, 1, 0, 1,
	1
};
#pragma pack(pop)

// Build Client Hello message with SNI extension if it's provided
static size_t BuildClientHello(TinyTLSContext * ctx, Binary & out, uint32_t * client_random, const char * sni, const Binary * session)
{
	// ### check bounds for client hello
	out.alloc(4096);

	size_t s = 0;

	TlsHead * t = (TlsHead *)(out.data);

	t->type = 0x16;
	t->version_major = 3;
	t->version_minor = 1;
	
	uint8_t * ptr = out.data + sizeof(TlsHead);

	uint32_t * hslen = (uint32_t *)ptr;

	ptr[4] = 3;
	ptr[5] = 1;

	ptr += 6;

	// generate client random
	{
		memcpy((uint32_t *)ptr, client_random, sizeof(uint32_t) * 8);
		ptr += sizeof(uint32_t) * 8;
	}

	// session id
	if (!session) {
		// no session id
		*ptr++ = 0;
	} else {
		*ptr++ = (uint8_t)session->length;
		memcpy(ptr, session->data, session->length);
		ptr += session->length;
	}

	//cipher suits & compression methods
	memcpy(ptr, ClentHelloCaps, sizeof(ClentHelloCaps));
	ptr += sizeof(ClentHelloCaps);

	if (sni && *sni) {
		// leave space for extensions
		uint8_t * exts = ptr + 2;
		uint8_t * ext = exts;

		//write SNI extension
		{
			*(uint16_t*)ext = 0x0;

			ext += 6;

			size_t len = strlen(sni);
			uint8_t * hn = ext;

			*hn++ = 0;
			*(uint16_t *)hn = bswap16(len);
			hn += 2;
			memcpy(hn, sni, len);

			len += (hn - ext);

			*(uint16_t *)(ext - 2) = bswap16(len);
			*(uint16_t *)(ext - 4) = bswap16(len + 2);

			ext += len;
		}

		*(uint16_t *)(exts - 2) = bswap16(ext - exts);
		ptr = ext;
	}

	s = (ptr - (uint8_t *)hslen);
	*hslen = bswap32(s - sizeof(uint32_t)) | HandshakeType::client_hello;
	
	t->length = bswap16(s);

	return (s + sizeof(TlsHead));
}

// Build Client Certificate message
static size_t BuildClientCertificate(TinyTLSContext * ctx, Binary & out, const uint8_t * certificate_list, size_t size)
{
	out.alloc(20 + size);

	size_t s = 0;

	TlsHead * t = (TlsHead *)(out.data);

	t->type = 0x16;
	t->version_major = 3;
	t->version_minor = 1;

	uint8_t * ptr = out.data + sizeof(TlsHead);

	uint32_t * hslen = (uint32_t *)ptr;

	ptr += sizeof(uint32_t);

	// full length of list
	*ptr++ = 0;
	*(uint16_t*)ptr = bswap16(size);
	ptr += sizeof(uint16_t);

	memcpy((uint32_t *)ptr, certificate_list, size);
	ptr += size;

	s = (ptr - (uint8_t *)hslen);
	*hslen = bswap32(s - sizeof(uint32_t)) | HandshakeType::certificate;

	t->length = bswap16(s);

	return (s + sizeof(TlsHead));
}

// Build Client Key Exchange message
// 
// This one is for RSA encryption. Not sure if it's possible to use 
// it in DH schemes
static size_t BuildClientKeyExchange(TinyTLSContext * ctx, Binary & out, uint8_t * encrypted_pms, size_t size)
{
	out.alloc(20 + size);

	size_t s = 0;

	TlsHead * t = (TlsHead *)(out.data);

	t->type = 0x16;
	t->version_major = 3;
	t->version_minor = 1;

	uint8_t * ptr = out.data + sizeof(TlsHead);

	uint32_t * hslen = (uint32_t *)ptr;

	ptr += sizeof(uint32_t);

	// generate client random
	*(uint16_t*)ptr = bswap16(size);
	ptr += sizeof(uint16_t);
	memcpy((uint32_t *)ptr, encrypted_pms, size);
	ptr += size;

	s = (ptr - (uint8_t *)hslen);
	*hslen = bswap32(s - sizeof(uint32_t)) | HandshakeType::client_key_exchange;

	t->length = bswap16(s);

	return (s + sizeof(TlsHead));
}

extern void EncryptRSA(TinyTLSContext * ctx, Binary & out, unsigned int size, const Binary & Modulus, const Binary & Exponent, const uint8_t * data, unsigned length);
extern void PrfGenerateBlock_v1_0(unsigned char * output, unsigned int outLen, const unsigned char * secret, unsigned sectretLen, const char * label, const unsigned char * seed, unsigned int seedLen);

#include "aes_hmac_sha.h"

class TinyTLSContextImpl : public TinyTLSContext
{
	typedef uint32_t Random[8];

	TTlsLink * link;

	uint8_t version_major;
	uint8_t version_minor;

	CipherSuite selected_cs;

	union{
		struct{
			Random client_random;
			Random server_random;
		};
		uint8_t master_prf_seed[64];
	};

	Binary session_id;

	CipherSuite active_cs;

	enum{
		HANDSHAKE_STARTED        = 0x0001,
		HANDSHAKE_HELLO          = 0x0002,
		HANDSHAKE_SERVER_CERT    = 0x0004,
		HANDSHAKE_SERVER_KEY     = 0x0008,
		HANDSHAKE_CERT_REQUEST   = 0x0010,
		HANDSHAKE_SERVER_DONE    = 0x0020,
		HANDSHAKE_CLIENT_FINISHED= 0x0030,
		HANDSHAKE_SERVER_FINISHED= 0x0040,

		HANDSHAKE_RESUMED        = 0x0100,

		CONNECTION_CLOSED        = 0x1000,
	};

	uint32_t handshake_completion;
	int32_t handshake_error;

	Binary & encrypted_pre_master_secret() { return key_block; }
	uint8_t master_secret[48];

	MD5_State handshake_messages_md5;
	SHA1_State handshake_messages_sha1;

	uint64_t client_seq_number;
	uint64_t server_seq_number;

	Binary key_block;

	uint8_t * client_MAC_secret;
	uint8_t * server_MAC_secret;
	uint8_t * client_key;
	uint8_t * server_key;
	uint8_t * client_IV;
	uint8_t * server_IV;

	uint32_t key_ready = 0;

public:

	Binary workBuf;
	Binary recvBuf;

	size_t recvOffset;
	size_t recvSize;

	AES128_HMAC_SHA active_encryption;
	AES128_HMAC_SHA active_decryption;

	TlsHead sendHead;

	TinyTLSContextImpl()
	{
		link = NULL;

		rng_ctx = 0;
		certificate_strogate = 0;

		// Not strictly necessary
		memset(master_secret, 0, sizeof(master_secret));
	}

	~TinyTLSContextImpl()
	{
	}

	void close()
	{
		if (handshake_completion == 0)
			return;

		if ((handshake_completion & CONNECTION_CLOSED) != 0)
			return;

		sendAlert(1, AlertType::close_notify);
		handshake_completion |= CONNECTION_CLOSED;
	}

	int connectionReady() const
	{
		if (handshake_completion & CONNECTION_CLOSED)
			return handshake_error;

		// check if handshakle complete
		if ((handshake_completion & (HANDSHAKE_CLIENT_FINISHED | HANDSHAKE_SERVER_FINISHED)) == (HANDSHAKE_CLIENT_FINISHED | HANDSHAKE_SERVER_FINISHED))
			return 1;
		// return handshake status
		return handshake_error;
	}

	void Init()
	{
		version_major = 3;
		version_minor = 1;

		selected_cs = TLS_NULL_WITH_NULL_NULL;
		
		memset(client_random, 0, sizeof(Random));
		memset(server_random, 0, sizeof(Random));

		active_cs = TLS_NULL_WITH_NULL_NULL;

		handshake_completion = 0;
		handshake_error = 0;

		md5Init(&handshake_messages_md5);
		sha1Init(&handshake_messages_sha1);

		client_seq_number = 0;
		server_seq_number = 0;

		sendHead.type = 0x17; //app data
		sendHead.version_major = version_major;
		sendHead.version_minor = version_minor;

		key_ready = 0;

		recvOffset = 0;
		recvSize = 0;

		if (!rng_ctx) {
			ttlsInitSystemRandomGenerator(this);
		}
	}

	int RecvServerPacket(TlsHead * head, Binary * buff);

	void PrepareKeyBlock()
	{
		//### does not support rekeying
		if (key_ready > 0)
			return;

		//TLS 1.1:
		//TLS_RSA_WITH_AES_128_CBC_SHA
		//  client_write_MAC_secret[SecurityParameters.hash_size]     20 b ??
		//  server_write_MAC_secret[SecurityParameters.hash_size]     20 b ??
		//  client_write_key[SecurityParameters.key_material_length]  16 b
		//  server_write_key[SecurityParameters.key_material_length]  16 b
		//  client_write_IV[SecurityParameters.IV_size]               16 b
		//  server_write_IV[SecurityParameters.IV_size]               16 b

		uint8_t key_seed[sizeof(master_prf_seed)];
		memcpy(key_seed, server_random, sizeof(server_random));
		memcpy(key_seed + sizeof(server_random), client_random, sizeof(client_random));

		//generate key material
		//key_block = PRF(SecurityParameters.master_secret, "key expansion", SecurityParameters.server_random + SecurityParameters.client_random);
		key_block.alloc(20 * 2 + 16 * 2 + 16 * 2);
		PrfGenerateBlock_v1_0(key_block.data, key_block.length, master_secret, 48, "key expansion", key_seed, sizeof(master_prf_seed));

		client_MAC_secret = key_block.data + 0;
		server_MAC_secret = key_block.data + 20;
		client_key = key_block.data + 40;
		server_key = key_block.data + 40 + 16;
		client_IV = key_block.data + 40 + 32;
		server_IV = key_block.data + 40 + 32 + 16;

		key_ready = 1;
	}

	void processServerCCS()
	{
		const uint32_t required = (HANDSHAKE_HELLO | HANDSHAKE_SERVER_CERT | HANDSHAKE_SERVER_KEY | HANDSHAKE_SERVER_DONE);

		// if we don't have all the required messages
		if ((handshake_completion & required) != required) {
			sendAlertPlain(2, AlertType::unexpected_message);
			handshake_error = TTLS_ERR_TAMPERED;
			return;
		}

		PrepareKeyBlock();

		active_decryption.InitDec(server_key, server_IV, server_MAC_secret);
		active_cs = selected_cs;
	}

	void processServerHello(int len, const uint8_t * srcdata)
	{
		const uint8_t * data = srcdata;

		// check minimum expected size: 4 bytes
		if (len < 4) {
			handshake_error = TTLS_ERR_BADMSG;
			return;
		}

		version_major = data[0];
		version_minor = data[1];

		if (version_major < 3 || (version_major == 3 && version_minor == 0)) {
			sendAlertPlain(2, AlertType::protocol_version);
			handshake_error = TTLS_ERR_INSECURE;
			return;
		}

		if (version_major >= 4 || version_minor >= 2) {
			sendAlertPlain(2, AlertType::protocol_version);
			handshake_error = TTLS_ERR_UNSUPPORTED;
			return;
		}

		// check minimum expected packet length 
		if (2 + sizeof(Random) + 1 > len) {
			handshake_error = TTLS_ERR_BADMSG;
			return;
		}
		memcpy(server_random, data + 2, sizeof(Random));

		data += 2 + sizeof(Random);

		// session id
		uint8_t sid_len = *data++;

		// check for overflow
		if (sid_len > 64 || ((data - srcdata) + sid_len > len)) {
			handshake_error = TTLS_ERR_BADMSG;
			return;
		}

		// server supports session resumption
		if (sid_len > 0) {
			if (session_id.length == sid_len && memcmp(session_id.data, data, session_id.length) == 0) {
				// session id matched - session will be resumed
				handshake_completion |= HANDSHAKE_RESUMED;
			} else {
				// erase session id and master secret
				session_id.alloc(sid_len);
				memcpy(session_id.data, data, sid_len);
			}
		} else {
			//### maybe we shouldn't
			//### in case we hit wrong server
			session_id.clear();
		}

		data += sid_len; //skip session id

		// check minimum expected packet length 
		if ((data - srcdata) + 3 > len) {
			handshake_error = TTLS_ERR_BADMSG;
			return;
		}

		selected_cs = data[0] | (data[1] << 8);

		// Enabled compression options are insecure! tinyTLS never asks for them.
		// See: https://community.qualys.com/blogs/securitylabs/2012/09/14/crime-information-leakage-attack-against-ssltls
		if (data[2] != 0) {
			sendAlertPlain(2, AlertType::handshake_failure);
			handshake_error = TTLS_ERR_INSECURE;
			return;
		}

		if (selected_cs != TLS_RSA_WITH_AES_128_CBC_SHA) {
			sendAlertPlain(2, AlertType::handshake_failure);
			handshake_error = TTLS_ERR_UNSUPPORTED;
			return;
		}

		// skip cipher suite and compression identifiers
		data += 3;

		// ### extensions ???
		// - currently none worth checking
		// - ### session tickets

		if (!(handshake_completion & HANDSHAKE_RESUMED)) {
			memset(master_secret, 0, sizeof(master_secret));
		} else {
			// skip all theese messages and jump straight to CCS and Finished
			handshake_completion |= HANDSHAKE_SERVER_CERT | HANDSHAKE_SERVER_KEY | HANDSHAKE_SERVER_DONE;
		}

		handshake_completion |= HANDSHAKE_HELLO;
	}

	void processHSCertificate(int len, const uint8_t * data)
	{
		//check minimum expected packet length
		if (len < 3) {
			sendAlertPlain(2, AlertType::unexpected_message);
			handshake_error = TTLS_ERR_BADMSG;
			return;
		}

		// chain length
		int dl = ((data[0] << 16) + (data[1] << 8) + (data[2]));
		const uint8_t * end = data + dl + 3;

		data += 3;
		len -= 3;

		if (len < dl) {
			sendAlertPlain(2, AlertType::decode_error);
			handshake_error = TTLS_ERR_BADMSG;
			return;
		}

		size_t certCount = 0;
		CertifacteBinary certs[MAX_CERTS];
		CertificateInfo certInfo[MAX_CERTS];

		while ((data != end) && (certCount < MAX_CERTS)) {
			//check minimum expected packet length
			if (data + 3 > end) {
				sendAlertPlain(2, AlertType::unexpected_message);
				handshake_error = TTLS_ERR_BADMSG;
				return;
			}

			//we are only interested in FIRST certificate
			size_t certlen = (size_t)(data[0] << 16) + (size_t)(data[1] << 8) + (size_t)(data[2]);
			data += 3;

			//check minimum expected packet length
			if (data + certlen > end) {
				sendAlertPlain(2, AlertType::unexpected_message);
				handshake_error = TTLS_ERR_BADMSG;
				return;
			}

			certs[certCount].length = certlen;
			certs[certCount].data = data;
			++certCount;

			data += certlen;
		}

		if (certCount <= 0 || certCount > MAX_CERTS) {
			sendAlertPlain(2, AlertType::bad_certificate);
			handshake_error = TTLS_ERR_BADMSG;
			return;
		}

		int trusted = VerifyCertificateChain(this, certs, certInfo, certCount);

		if (trusted <= 0) {
			sendAlertPlain(2, AlertType::certificate_unknown);
			handshake_error = TTLS_ERR_INSECURE;
			return;
		}

		PKCS1_RSA_PublicKey keyComp;
		if (Extract_PKCS1_RSA_PublicKeyComponents(&keyComp, certInfo[0].publicKey.length, certInfo[0].publicKey.data) < 0) {
			sendAlertPlain(2, AlertType::unsupported_certificate);
			handshake_error = TTLS_ERR_BADMSG;
			return;
		}
			

		handshake_completion |= HANDSHAKE_SERVER_CERT;
		handshake_completion |= HANDSHAKE_SERVER_KEY; //### should not set it when using PFS (DH or ECDH)

		// check for insecure RSA parameters
		if (keyComp.modulus.length < 128) {
			sendAlertPlain(2, AlertType::insufficient_security);
			handshake_error = TTLS_ERR_INSECURE;
			return;
		}

		{
			// sometimes modulus values is larger by one or two bytes for no reason
			// round down to multiple of 4
			unsigned res_len = keyComp.modulus.length & ~0x3;

			// this value won't survive long - we encrypt it
			uint8_t pre_master_secret[48];

			// generate pre_master_secret
			this->rng_ctx->GenerateRandomBytes(this, pre_master_secret + 2, sizeof(pre_master_secret) - 2);
			pre_master_secret[0] = version_major;
			pre_master_secret[1] = version_minor;

			// encrypt pre_master_secret (prepare key exchange message)
			EncryptRSA(this, encrypted_pre_master_secret(), res_len,
					   keyComp.modulus,
					   keyComp.exponent,
					   pre_master_secret,
					   48);

			// generate master_secret
			PrfGenerateBlock_v1_0(master_secret, 48, pre_master_secret, 48, "master secret", master_prf_seed, sizeof(master_prf_seed));

			//writeKeyLogClientRandom((uint8_t*)client_random, master_secret);
		}
	}

	void processHSCertRequest(int len, const uint8_t * data)
	{
		//check minimum expected packet length
		if (len < 3) {
			sendAlertPlain(2, AlertType::unexpected_message);
			handshake_error = TTLS_ERR_BADMSG;
			return;
		}

		// tls requires us to sendcertificate if required by server even if empty
		handshake_completion |= HANDSHAKE_CERT_REQUEST;

		//### verify certificate type matches supported certificates
	}

	int processHSDone()
	{
		handshake_completion |= HANDSHAKE_SERVER_DONE;

		const uint32_t required = (HANDSHAKE_HELLO | HANDSHAKE_SERVER_CERT | HANDSHAKE_SERVER_KEY | HANDSHAKE_SERVER_DONE);

		// if we don't have all the required messages
		// notice - resumed sessions are not allowed here
		if ((handshake_completion & required) != required || (handshake_completion & HANDSHAKE_RESUMED) != 0) {
			sendAlertPlain(2, AlertType::unexpected_message);
			handshake_error = TTLS_ERR_TAMPERED;
			return 0;
		}

		// server requesting client certificate
		//### error - unsupported
		if( handshake_completion & HANDSHAKE_CERT_REQUEST ) {
			sendAlertPlain(2, AlertType::close_notify);
			handshake_error = TTLS_ERR_UNSUPPORTED;
			return 0;
		}

		return 1;
	}

	int processHSFinished(int len, const uint8_t * data)
	{
		//check finished data
		uint8_t handshake_messages_verify[16 + 20];

		// this message has fixed length
		if (len != 12) {
			sendAlertPlain(2, AlertType::decode_error);
			handshake_error = TTLS_ERR_BADMSG;
			return 0;
		}

		if (handshake_completion & HANDSHAKE_RESUMED) {
			// non-destructive
			MD5_State state_copy_md5; memcpy(&state_copy_md5, &handshake_messages_md5, sizeof(MD5_State));
			SHA1_State state_copy_sha1; memcpy(&state_copy_sha1, &handshake_messages_sha1, sizeof(SHA1_State));

			md5Finish(&state_copy_md5, (uint32_t*)&handshake_messages_verify[0]);
			sha1Finish(&state_copy_sha1, (uint32_t*)&handshake_messages_verify[16]);
		} else {
			// destructive
			md5Finish(&handshake_messages_md5, (uint32_t*)&handshake_messages_verify[0]);
			sha1Finish(&handshake_messages_sha1, (uint32_t*)&handshake_messages_verify[16]);
		}

		uint8_t finishedBody[12];

		PrfGenerateBlock_v1_0(finishedBody, 12, master_secret, 48, "server finished", handshake_messages_verify, sizeof(handshake_messages_verify));

		uint8_t x = 0;
		for (unsigned int i = 0; i < sizeof(finishedBody); ++i) x |= finishedBody[i] ^ data[i];

		if (x > 0) {
			sendAlertPlain(2, AlertType::decrypt_error);
			handshake_error = TTLS_ERR_TAMPERED;
			return 0;
		}

		handshake_completion |= HANDSHAKE_SERVER_FINISHED;
		return 1;
	}

	void processHandshakePacket(int packlen, const uint8_t * data, const TlsHead * head)
	{
		Binary dec_packet;

		if (active_cs != TLS_NULL_WITH_NULL_NULL) {
			int32_t l = active_decryption.UnWrapPacket(dec_packet, (const uint8_t *)head, data, packlen);
			if (l < 0) {
				// packet has invalid
				// tinyTLS will not send alert even if standard recomends it.
				//sendAlertPlain(2, AlertType::unexpected_message);

				handshake_error = TTLS_ERR_TAMPERED;
				return;
			}
			data = dec_packet.data;
			packlen = l;
		}

		while(packlen > 0)
		{
			uint32_t head = *((uint32_t*)data);
			uint32_t len = ((head & 0xFF00) << 8) + ((head & 0xFF0000) >> 8) + ((head & 0xFF000000) >> 24);

			data += sizeof(uint32_t);

			bool finished = false;

			int res = 0;
	
			switch(head & 0xFF)
			{
			case HandshakeType::server_hello: //server hello
				processServerHello(len, data);
				break;
			case HandshakeType::server_hello_done: //server hello done
				finished = (processHSDone() == 1);
				break;
			case HandshakeType::certificate: //server certificate
				processHSCertificate(len, data);
				break;
			case HandshakeType::certificate_request: //server certificate requiest
				processHSCertRequest(len, data);
				break;
			case HandshakeType::finished: //server finished
				res = processHSFinished(len, data);
				// time to finish resumed handshake
				finished = ((handshake_completion & HANDSHAKE_RESUMED) != 0) && (res > 0);
				break;
			}

			//save for finshed message
			md5Update(&handshake_messages_md5, data - sizeof(uint32_t), len + sizeof(uint32_t));
			sha1Update(&handshake_messages_sha1, data - sizeof(uint32_t), len + sizeof(uint32_t));

			if (finished) {
				FinishClientHandshake();
				return;
			}

			data += len;
			packlen -= len + sizeof(uint32_t);
		}
		return;
	}

	void BeginClientHandshake()
	{
		if (handshake_completion & HANDSHAKE_STARTED)
			return;

		// build proper hello packet
		selected_cs = TLS_NULL_WITH_NULL_NULL;

		md5Init(&handshake_messages_md5);
		sha1Init(&handshake_messages_sha1);

		client_random[0] = (uint32_t)time(NULL);
		this->rng_ctx->GenerateRandomBytes(this, (uint8_t *)(client_random + 1), sizeof(client_random) - 4);

		// NOTE: using truncated result!
		size_t packsize = BuildClientHello(this, workBuf, client_random, (const char *)HostName, &session_id);

		//save for finshed message
		md5Update(&handshake_messages_md5, (const uint8_t*)workBuf.data + sizeof(TlsHead), packsize - sizeof(TlsHead));
		sha1Update(&handshake_messages_sha1, (const uint8_t*)workBuf.data + sizeof(TlsHead), packsize - sizeof(TlsHead));

		// ### check errors
		link->send(link->context, (const uint8_t *)workBuf.data, packsize);
		link->flush(link->context);

		handshake_completion = HANDSHAKE_STARTED;
	}

	void FinishClientHandshake()
	{
		TlsHead head;
		head.type = 0x16;
		head.version_major = 3;
		head.version_minor = 1;

		// decide if session resumption is in efffect
		if (handshake_completion & HANDSHAKE_RESUMED) {

			// Hello must be received
			if (!(handshake_completion & HANDSHAKE_HELLO)) {
				sendAlertPlain(2, AlertType::unexpected_message);
				handshake_error = TTLS_ERR_TAMPERED;
				return;
			}

			// send abbreviated client handshake
			//   [ChangeCipherSpec]
			//   Finished
		} else {
			// send client handshake
			//   Certificate*   -- unsupported
			//   ClientKeyExchange 
			//   CertificateVerify* -- unsupported
			//   [ChangeCipherSpec]
			//   Finished

			//client certificate
			if (handshake_completion & HANDSHAKE_CERT_REQUEST) {
				//### no certificate for now
				size_t packsize = BuildClientCertificate(this, workBuf, NULL, 0);

				//save for finshed message
				md5Update(&handshake_messages_md5, (const uint8_t*)workBuf.data + 5, packsize - sizeof(TlsHead));
				sha1Update(&handshake_messages_sha1, (const uint8_t*)workBuf.data + 5, packsize - sizeof(TlsHead));

				// ### check errors
				link->send(link->context, (const uint8_t *)workBuf.data, packsize);
			}

			//client key exchange
			{
				unsigned int res_length = encrypted_pre_master_secret().length;

				size_t packsize = BuildClientKeyExchange(this, workBuf, encrypted_pre_master_secret().data, encrypted_pre_master_secret().length);

				//save for finshed message
				md5Update(&handshake_messages_md5, (const uint8_t*)workBuf.data + 5, packsize - sizeof(TlsHead));
				sha1Update(&handshake_messages_sha1, (const uint8_t*)workBuf.data + 5, packsize - sizeof(TlsHead));

				// ### check errors
				link->send(link->context, (const uint8_t *)workBuf.data, packsize);

				// destroy the key
				encrypted_pre_master_secret().clear();
			}

			//### client certificate verify
			if (handshake_completion & HANDSHAKE_CERT_REQUEST) {
			}

			PrepareKeyBlock();
		}

		//change-cypher-spec
		{
			// ### check errors
			link->send(link->context, (const uint8_t *)CCSPacket, sizeof(CCSPacket));

			active_encryption.InitEnc(client_key, client_IV, client_MAC_secret);
		}

		//client finished
		{
			uint8_t handshake_messages_verify[16 + 20];

			// save a copy of hash contexts
			//### this is slow - need non-destructive Finish for hashes
			MD5_State state_copy_md5; memcpy(&state_copy_md5, &handshake_messages_md5, sizeof(MD5_State));
			SHA1_State state_copy_sha1; memcpy(&state_copy_sha1, &handshake_messages_sha1, sizeof(SHA1_State));

			md5Finish(&state_copy_md5, (uint32_t*)&handshake_messages_verify[0]);
			sha1Finish(&state_copy_sha1, (uint32_t*)&handshake_messages_verify[16]);

			uint8_t finishedBody[16];
			*((uint32_t *)finishedBody) = 0x0c000014;

			PrfGenerateBlock_v1_0(finishedBody + 4, 12, master_secret, 48, "client finished", handshake_messages_verify, sizeof(handshake_messages_verify));

			//save for finshed message
			md5Update(&handshake_messages_md5, (const uint8_t*)finishedBody, sizeof(finishedBody));
			sha1Update(&handshake_messages_sha1, (const uint8_t*)finishedBody, sizeof(finishedBody));

			Binary pack;
			active_encryption.WrapPacket(pack, (uint8_t *)&head, finishedBody, sizeof(finishedBody));

			// ### check errors
			link->send(link->context, (const uint8_t *)&head, sizeof(head));
			link->send(link->context, (const uint8_t *)pack.data, pack.length);
		}

		// ### check errors
		link->flush(link->context);

		handshake_completion |= HANDSHAKE_CLIENT_FINISHED;
	}

	// send alert with encryption - or without
	void sendAlert(uint8_t level, uint8_t code)
	{
		if (active_cs == TLS_NULL_WITH_NULL_NULL) {
			sendAlertPlain(level, code);
			return;
		}

		TlsHead head;
		head.type = 0x15;
		head.version_major = 3;
		head.version_minor = 1;

		uint8_t packet[2];
		packet[0] = level;
		packet[1] = code;

		int32_t pl = active_encryption.WrapPacket(workBuf, (uint8_t*)&head, packet, 2);

		// ignore sender errors here
		// alerts are being sent in best-effort way
		link->send(link->context, (const uint8_t *)&head, sizeof(head));
		link->send(link->context, (const uint8_t *)workBuf.data, pl);

		// indicate connection close on errors
		if (level == 2) handshake_completion |= CONNECTION_CLOSED;
	}

	void sendAlertPlain(uint8_t level, uint8_t code)
	{
		uint8_t packet[7];
		packet[0] = 0x15;
		packet[1] = version_major;
		packet[2] = version_minor;
		packet[3] = 0;
		packet[4] = 2;
		packet[5] = level;
		packet[6] = code;
		link->send(link->context, (const uint8_t *)packet, 7);

		// indicate connection close on errors
		if (level == 2) handshake_completion |= CONNECTION_CLOSED;
	}

	int sendData(const uint8_t * data, uint32_t length)
	{
		do {
			uint32_t l = length > 16362 ? 16362 : length;

			int32_t pl = active_encryption.WrapPacket(workBuf, (uint8_t*)&sendHead, data, l);

			//### check errors
			link->send(link->context, (const uint8_t *)&sendHead, sizeof(sendHead));
			link->send(link->context, (const uint8_t *)workBuf.data, pl);

			length -= l;
			data += l;
		} while (length > 0);
		return 1;
	}

	// this will restart client comunication!
	int SetLink(TTlsLink * link)
	{
		// ### verify link structure

		this->link = link;
		this->BeginClientHandshake();
		return 0;
	}

	int Handshake()
	{
		TlsHead head;
		Binary packet;

		int rel_length = 0;

		while (1) {
			int x = connectionReady();
			if (x != 0) return x;

			rel_length = this->RecvServerPacket(&head, &packet);
			if (rel_length <= 0) return 0;
#ifdef TINYTLS_DEBUG
			printf("TLS_PACKET: %02X,   Ver %d.%d   Len %d\n",
				   head.type, head.version_major, head.version_minor, packet.length);
#endif

			if (head.type == 0x16) { //handshake
				processHandshakePacket(packet.length, packet.data, &head);
			} else if (head.type == 0x14) { //ccs
				processServerCCS();
			} else {
				// out-of-order packet - fail connection
				//PrintHex(packet.data, packet.length, 0);
				sendAlert(2, AlertType::unexpected_message);
				handshake_error = TTLS_ERR_BADMSG;
			}
		}
	}

	intptr_t ReceiveData(uint8_t * buffer, size_t size);
};

static const size_t TlsRecordLimit = (1 << 14) + (1 << 10);

int TinyTLSContextImpl::RecvServerPacket(TlsHead * head, Binary * buff)
{
	int r = 0;
	size_t l = 0;

	r = link->recv(link->context, (uint8_t*)head, 5);

	if (r < 0) {
		//printf("recv error = %d\n", link->geterror(link->context));
		return r;
	}

	if (r != 5) {
		return 0;
	}

	if (head->type < 0x14 || head->type > 0x17) {
		return TTLS_ERR_BADMSG;
	}
	if (head->version_major < 3 || (head->version_major == 3 && head->version_minor < 1)) {
		return TTLS_ERR_INSECURE;
	}

	l = ((head->length >> 8) & 0xFF) + ((head->length & 0xFF) << 8);
	if (l > TlsRecordLimit) {
		sendAlert(2, AlertType::record_overflow);
		return TTLS_ERR_BADMSG;
	}

	buff->alloc(l);

	uint8_t * p = buff->data;

	while (l > 0) {
		size_t rlim = (l > link->read_limit) ? (link->read_limit) : (l);

		r = link->recv(link->context, p, rlim);
		if (r <= 0) break;

		p += r;
		l -= r;
	}

	if (l != 0) {
		return r; // return last error code
	}

	// return length of read data
	return buff->length;
}

intptr_t TinyTLSContextImpl::ReceiveData(uint8_t * buffer, size_t size)
{
	// check for handshake state
	int32_t l = 0;
	int r = connectionReady();

	if (r <= 0) return r;

	TlsHead head;

	size_t ret = 0;

	for (;;) {
		if (recvSize >= size) {
			const uint8_t * in = (recvBuf.data + recvOffset);
			memcpy(buffer, in, size);
			recvSize -= size;
			recvOffset += size;
			return size;
		} else if (recvSize > 0) {
			const uint8_t * in = (recvBuf.data + recvOffset);
			memcpy(buffer, in, recvSize);
			size -= recvSize;
		}

	get_packet:
		// receive another packet
		r = RecvServerPacket(&head, &workBuf);
		if (r == 0) {
			size_t s = recvSize;
			recvSize = 0;
			return s;
		}
		if (r < 0) return r;

		// try to decode packet
		l = active_decryption.UnWrapPacket(recvBuf, (const uint8_t *)&head, workBuf.data, workBuf.length);
		if (l < 0) return l;

		// ignore empty packets
		if (l == 0)	goto get_packet;

		if (head.type == 0x15 && l == 2) {
			if (recvBuf.data[0] == 1 && recvBuf.data[1] == 0) { // connection close
				size_t s = recvSize;
				recvSize = 0;

				close();
				return s;
			} else if (recvBuf.data[0] != 1) {
				// kill connection on alerts
				recvSize = 0;
				close();
				return TTLS_ERR_BADMSG;
			} else {
				// ignore warning alert
				//### might not be what we want
			}
		} else if (head.type != 0x17) {
			// unexpected message
			recvSize = 0;
			close();
			return TTLS_ERR_BADMSG;
		}

		// prepare for data copying
		recvOffset = 0;
		recvSize = l;
		continue;
	}
}

//-------------------------------------------------------------------

TinyTls * ttlsCreateContext()
{
	TinyTLSContextImpl * t = new TinyTLSContextImpl();
	t->Init();

	return t;
}

void ttlsFreeContext(TinyTls * context)
{
	TinyTLSContextImpl * t = (TinyTLSContextImpl *)context;
	// close any outgoing connections
	t->close();
	delete t;
}

void ttlsReset(TinyTls * context)
{
	TinyTLSContextImpl * t = (TinyTLSContextImpl *)context;
	// close any outgoing connections
	t->close();
	// restore connection to original state
	t->Init();
}

void ttlsSetLink(TinyTls * context, TTlsLink * link)
{
	TinyTLSContextImpl * t = (TinyTLSContextImpl *)context;
	t->SetLink(link);
}

void ttlsSetHostname(TinyTls * context, const char * hostname)
{
	TinyTLSContextImpl * t = (TinyTLSContextImpl *)context;
	t->HostName = hostname;
}

intptr_t ttlsHandshake(TinyTls * context)
{
	TinyTLSContextImpl * t = (TinyTLSContextImpl *)context;

	return (intptr_t)t->Handshake();
}
intptr_t ttlsSend(TinyTls * context, const uint8_t * buffer, size_t size)
{
	TinyTLSContextImpl * t = (TinyTLSContextImpl *)context;

	return (intptr_t)t->sendData((const uint8_t*)buffer, size);
}

//intptr_t ttlsSkip(TinyTls * context, size_t size);
//intptr_t ttlsFlush(TinyTls * context);

intptr_t ttlsRecv(TinyTls * context, uint8_t * buffer, size_t size)
{
	TinyTLSContextImpl * state = (TinyTLSContextImpl *)context;
	return state->ReceiveData(buffer, size);
}

void ttlsUseCertStorage(TinyTls * context, struct TinyTLSCertificateStorage * cs)
{
	context->certificate_strogate = cs;
}
