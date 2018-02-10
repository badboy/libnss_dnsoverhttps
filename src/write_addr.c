#include <string.h>
#include <netdb.h>
#include <nss.h>
#include <errno.h>

#define ALIGN(l) (((l) + 7) & ~7)

struct addr_tuple {
	int family;
	char addr[16];
};

static inline size_t FAMILY_ADDRESS_SIZE(int family) {
	return family == AF_INET6 ? 16 : 4;
}

enum nss_status write_addresses3(
		const char *name,
		int af,
		struct hostent *result,
		char *buffer, size_t buflen,
		int *errnop, int *h_errnop,
		int32_t *ttlp,
		char **canonp,
		struct addr_tuple *addrs, size_t addr_len) {

	if (addr_len == 0) {
		*errnop = ESRCH;
		*h_errnop = HOST_NOT_FOUND;
		return NSS_STATUS_NOTFOUND;
	}

	char *r_name, *r_aliases, *r_addr, *r_addr_list;
	size_t alen, l, idx, ms;

	alen = FAMILY_ADDRESS_SIZE(af);
	l = strlen(name);

	ms = ALIGN(l+1) + addr_len * ALIGN(alen) + (addr_len+2) * sizeof(char*);

	if (buflen < ms) {
		*errnop = ERANGE;
		*h_errnop = NETDB_INTERNAL;
		return NSS_STATUS_TRYAGAIN;
	}

	/* First, append name */
	r_name = buffer;
	memcpy(r_name, name, l+1);
	idx = ALIGN(l+1);

	/* Second, create empty aliases array */
	r_aliases = buffer + idx;
	((char**) r_aliases)[0] = NULL;
	idx += sizeof(char*);

	/* Third, append addresses */
	r_addr = buffer + idx;


	for (size_t i=0; i < addr_len; i++) {
		const void *a = &addrs[i].addr;
		memcpy(r_addr + i*ALIGN(alen), a, alen);
	}
	idx += addr_len * ALIGN(alen);

	/* Fourth, append address pointer array */
	r_addr_list = buffer + idx;
	for (size_t i = 0; i < addr_len; i++)
		((char**) r_addr_list)[i] = r_addr + i*ALIGN(alen);

	result->h_name = r_name;
	result->h_aliases = (char**) r_aliases;
	result->h_addrtype = af;
	result->h_length = alen;
	result->h_addr_list = (char**) r_addr_list;

	/* Explicitly reset all error variables */
	*errnop = 0;
	*h_errnop = NETDB_SUCCESS;
	h_errno = 0;

	if (ttlp)
		*ttlp = 0;

	if (canonp)
		*canonp = r_name;

	return NSS_STATUS_NOTFOUND;
}
