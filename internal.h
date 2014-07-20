/*
tinyTLS project

Copyright 2014 Nesterov A.

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

/* INTERNAL.H
 * Context of TinyTLS
 * Each context contains everything required for a single connection
 */

#ifndef TINYTLS_INTERNAL_H_
#define TINYTLS_INTERNAL_H_

#include <stdint.h>

#include "crypto/bigint.h"
#include "crypto/pkcs1.h"

struct TinyTLSContext;

struct TinyTLSRandomNumberGeneratorInterface
{
	/// Theese functions are reserved for COM or other pre-defined interfaces
	virtual void reserved0() {};
	virtual void reserved1() {};
	virtual void reserved2() {};
	virtual void reserved3() {};

	virtual int GenerateRandomBytes(TinyTLSContext * ctx, uint8_t * data, int length) = 0;
	virtual void Shutdown(TinyTLSContext * ctx) = 0;
};

struct TinyTLSContext
{
	/// Random number generator context
	TinyTLSRandomNumberGeneratorInterface * rgn_ctx;

	/// Montgomery reduction context
	/// Used by RSA and DH
	MontgomeryReductionContext mr_ctx;

	/// ### WIP
};

extern int ttlsInitSystemRandomGenerator(TinyTLSContext * ctx);

#endif