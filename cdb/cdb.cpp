/* Public domain. */

#include <string.h>
#include "cdb.h"

static uint32_t cdb_hashadd(uint32_t h, uint8_t c)
{
	h += (h << 5);
	return h ^ c;
}

static uint32_t cdb_hash(const uint8_t * buf, unsigned int len)
{
	uint32_t h = 5381;
	while (len) {
		h = cdb_hashadd(h, *buf++);
		--len;
	}
	return h;
}

#define uint32_unpack(S, U) (*(U) = *(const uint32_t *)(S))

void cdb_free(struct cdb *c)
{
	if (c->map) {
		c->size = 0;
		c->map = 0;
	}
}

void cdb_findstart(struct cdb *c)
{
	c->loop = 0;
}

void cdb_init(struct cdb * c, const uint8_t * map, size_t size)
{
	cdb_free(c);
	cdb_findstart(c);

	c->map = map;
	c->size = size;
}

int cdb_read(struct cdb *c, uint8_t * buf, size_t len, uint32_t pos)
{
	if (c->map) {
		if ((pos > c->size) || (c->size - pos < len)) return -1;
		memcpy(buf, c->map + pos, len);
	}
	return 0;
}

static int match(struct cdb *c, const uint8_t * key, size_t len, uint32_t pos)
{
	uint8_t buf[32];
	size_t n;

	while (len > 0) {
		n = sizeof(buf);
		if (n > len) n = len;
		if (cdb_read(c, buf, n, pos) < 0) return -1;
		if (memcmp(buf, key, n) != 0) return 0;
		pos += n;
		key += n;
		len -= n;
	}
	return 1;
}

int cdb_findnext(struct cdb *c, const uint8_t * key, size_t len)
{
	uint8_t buf[8];
	uint32_t pos;
	uint32_t u;

	if (!c->loop) {
		u = cdb_hash(key, len);
		if (cdb_read(c, buf, 8, (u << 3) & 2047) == -1) 
			return -1;

		uint32_unpack(buf + 4, &c->hslots);

		if (!c->hslots) return 0;

		uint32_unpack(buf, &c->hpos);
		c->khash = u;
		u >>= 8;
		u %= c->hslots;
		u <<= 3;
		c->kpos = c->hpos + u;
	}

	while (c->loop < c->hslots) {
		if (cdb_read(c, buf, 8, c->kpos) == -1) return -1;
		uint32_unpack(buf + 4, &pos);

		if (!pos) return 0;

		c->loop += 1;
		c->kpos += 8;
		if (c->kpos == c->hpos + (c->hslots << 3)) c->kpos = c->hpos;
		uint32_unpack(buf, &u);
		if (u == c->khash) {
			if (cdb_read(c, buf, 8, pos) == -1) return -1;
			uint32_unpack(buf, &u);
			if (u == len) {
				switch (match(c, key, len, pos + 8)) {
				case -1:
					return -1;
				case 1:
					uint32_unpack(buf + 4, &c->dlen);
					c->dpos = pos + 8 + len;
					return 1;
				}
			}
		}
	}

	return 0;
}

int cdb_find(struct cdb *c, const uint8_t * key, size_t len)
{
	cdb_findstart(c);
	return cdb_findnext(c, key, len);
}
