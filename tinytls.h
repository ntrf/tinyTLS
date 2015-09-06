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

#ifndef TINY_TLS_H_
#define TINY_TLS_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct TinyTLSContext;
typedef struct TinyTLSContext TinyTls;

/// Link descriptor
///
/// Use this structure to supply your own implementation of socket
/// to tinyTLS

struct TTlsLink
{
	void * context;
	size_t read_limit;
	size_t write_limit;
	int (* recv)(void * context, uint8_t * buffer, size_t size);
	int (* send)(void * context, const uint8_t * buffer, size_t size);
	int (* flush)(void * context);
	int (*geterror)(void * context);
};

TinyTls * ttlsCreateContext();
void ttlsFreeContext(TinyTls *);

/// Reset handshake state for TLS connection
void ttlsReset(TinyTls * context);

/// Select link for specific context
///
/// Sets an active link object for current context. Link object will be used for
/// all subsequent network operations
///
/// `link`       link descriptor to attach to context
///
/// NOTE: this will reset the handshake state
void ttlsSetLink(TinyTls * context, TTlsLink * link);

/// Set hostname for specific context
/// 
/// `hostname`   name used for SNI packet if provided as well as for certificate
///              validation
///
/// NOTE: this will invalidate certificate cache
void ttlsSetHostname(TinyTls * context, const char * hostname);

/// Handles handshake between servers
/// 
/// This function must be called before any other data processing can be done.
/// Keep calling this function in loop until it returns non-zero value.
///
/// returns 0 if handshake is incomplete and once of the network functions returned zero
/// returns >0 if handshake is complete or became complete during previous call
/// returns <0 if handshake failed co complete
intptr_t ttlsHandshake(TinyTls * context);

/// Send data to server
intptr_t ttlsSend(TinyTls * context, const uint8_t * buffer, size_t size);

/// Receive data form server
intptr_t ttlsRecv(TinyTls * context, uint8_t * buffer, size_t size);

/// Receive data from server but don't store it
intptr_t ttlsSkip(TinyTls * context, size_t size);

/// Flush all outgoing data
intptr_t ttlsFlush(TinyTls * context);

struct TinyTLSCertificateStorage;

/// Create certificate storage and load contents from memory
struct TinyTLSCertificateStorage * ttlsCreateCertStorage(const uint8_t * mem, size_t size);

/// Destroy certificate storage
void ttlsFreeCertStorage(struct TinyTLSCertificateStorage *);

/// Use certificate storage for context
void ttlsUseCertStorage(TinyTls * context, struct TinyTLSCertificateStorage *);

enum TTlsError
{
	/// Negotiated parameters can't be used for secure communication. Server 
	/// reconfiguration is required.
	TTLS_ERR_INSECURE = -115001,

	/// Negotiated parameters are not supported by tinyTLS and communication 
	/// could not be continued.
	TTLS_ERR_UNSUPPORTED = -115002,

	/// Connection between peers is most likely affected by a third-praty. 
	/// tinyTLS will break the connection to ensure security.
	TTLS_ERR_TAMPERED = -115003,

	/// Unexpected message format received. Could be possible in case of a
	/// connection error or malicios actions from third-party.
	TTLS_ERR_BADMSG = -115004,
};

#ifdef __cplusplus
}
#endif

#endif
