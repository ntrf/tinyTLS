/* Public domain. */

#ifndef CDB_H
#define CDB_H

#include <stdint.h>

struct cdb 
{
	const uint8_t * map; /* 0 if no map is available */
	uint32_t size; /* initialized if map is nonzero */
	uint32_t loop; /* number of hash slots searched under this key */
	uint32_t khash; /* initialized if loop is nonzero */
	uint32_t kpos; /* initialized if loop is nonzero */
	uint32_t hpos; /* initialized if loop is nonzero */
	uint32_t hslots; /* initialized if loop is nonzero */
	uint32_t dpos; /* initialized if cdb_findnext() returns 1 */
	uint32_t dlen; /* initialized if cdb_findnext() returns 1 */
};

extern void cdb_free(struct cdb *);
extern void cdb_init(struct cdb *, const uint8_t * map, size_t size);

extern int cdb_read(struct cdb *, uint8_t * buf, size_t len, uint32_t pos);

extern void cdb_findstart(struct cdb *);
extern int cdb_findnext(struct cdb *, const uint8_t * key, size_t len);
extern int cdb_find(struct cdb *, const uint8_t * key, size_t len);

#define cdb_datapos(c) ((c)->dpos)
#define cdb_datalen(c) ((c)->dlen)

#endif
