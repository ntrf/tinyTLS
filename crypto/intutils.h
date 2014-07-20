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
#ifndef TINYTLS_INTUTILS_H_
#define TINYTLS_INTUTILS_H_

#include <stdint.h>

#ifdef ARM_ASSEMBLY

//### untested

static inline __attribute__((always_inline))
uint32_t arm_ror_imm(uint32_t v, uint32_t sh) {
  register uint32_t d;
#if 1
  __asm__("ROR %0, %1, %2" : "=r" (d) : "r" (v), "i" (sh));
#else
  __asm__("MOV %0, %1, ROR %2\n" : "=r"(d) : "r"(v), "M"(sh));
#endif
  return d;
}

#define ror(v, s) arm_ror_imm(v, s)
#define rol(v, s) arm_ror_imm(v, 32-s)

#define bswap32(v) __builtin_bswap32(val)

#else

static inline uint32_t ror(uint32_t v, uint32_t s) { return (v >> s) | (v << (32-s)); }
static inline uint32_t rol(uint32_t v, uint32_t s) { return (v >> (32-s)) | (v << s); }

static inline uint32_t bswap32(uint32_t v) { return rol(v & 0xFF00FF00, 8) | ror(v & 0x00FF00FF, 8); }
static inline uint16_t bswap16(uint16_t v) { return ((v & 0xFF00) >> 8) | ((v & 0x00FF) << 8); }

#endif


#endif