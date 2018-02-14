#include <string.h>
#include <netdb.h>
#include <nss.h>
#include <errno.h>

#define ALIGN(l) (((l) + 7) & ~7)

struct addr_tuple {
	int family;
	char addr[16];
};

enum nss_status write_addresses4(
		const char *name,
		struct gaih_addrtuple **pat,
		char *buffer, size_t buflen,
		int *errnop, int *h_errnop,
		int32_t *ttlp,
		struct addr_tuple *addrs, size_t addr_len) {

	if (addr_len == 0) {
		*errnop = ESRCH;
		*h_errnop = HOST_NOT_FOUND;
		return NSS_STATUS_NOTFOUND;
	}

	/* First, append name */
	char *r_name;
	r_name = buffer;
	size_t l = strlen(name);
	size_t ms = ALIGN(l+1) + ALIGN(sizeof(struct gaih_addrtuple)) * addr_len;
	if (buflen < ms) {
		*errnop = ERANGE;
		*h_errnop = NETDB_INTERNAL;
		return NSS_STATUS_TRYAGAIN;
	}

	memcpy(r_name, name, l+1);
	int idx = ALIGN(l+1);

	/* Second, append addresses */
	struct gaih_addrtuple *r_tuple, *r_tuple_first = NULL;
	r_tuple_first = (struct gaih_addrtuple*) (buffer + idx);

	for (size_t i=0; i < addr_len; i++) {
		struct addr_tuple *in_tuple = (struct addr_tuple*) &addrs[i];
		r_tuple = (struct gaih_addrtuple*) (buffer + idx);
		r_tuple->next = i == addr_len-1 ? NULL : (struct gaih_addrtuple*) ((char*) r_tuple + ALIGN(sizeof(struct gaih_addrtuple)));

		r_tuple->name = r_name;
		r_tuple->scopeid = 0;
		r_tuple->family = in_tuple->family;
		memcpy(r_tuple->addr, &in_tuple->addr, 16);

		idx += ALIGN(sizeof(struct gaih_addrtuple));
	}

	if (*pat) {
		**pat = *r_tuple_first;
	}
	else {
		*pat = r_tuple_first;
	}

	if (ttlp)
		*ttlp = 0;

	*errnop = 0;
	*h_errnop = NETDB_SUCCESS;
	h_errno = 0;

	return NSS_STATUS_SUCCESS;
}

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

	return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_dnsoverhttps_gethostbyname3_r(
		const char *name,
		int af,
		struct hostent *result,
		char *buffer, size_t buflen,
		int *errnop, int *h_errnop,
		int32_t *ttlp,
		char **canonp);


enum nss_status _nss_dnsoverhttps_gethostbyname2_r(
		const char *name,
		int af,
		struct hostent *host,
		char *buffer, size_t buflen,
		int *errnop, int *h_errnop) {
	return _nss_dnsoverhttps_gethostbyname3_r(
			name,
			af,
			host,
			buffer, buflen,
			errnop, h_errnop,
			NULL,
			NULL);
}

enum nss_status _nss_dnsoverhttps_gethostbyname_r(
                const char *name,
                struct hostent *host,
                char *buffer, size_t buflen,
				int *errnop, int *h_errnop) {
	enum nss_status ret = NSS_STATUS_NOTFOUND;

	ret = _nss_dnsoverhttps_gethostbyname3_r(
			name,
			AF_INET6,
			host,
			buffer, buflen,
			errnop, h_errnop,
			NULL,
			NULL);

	if (ret == NSS_STATUS_NOTFOUND)
		ret = _nss_dnsoverhttps_gethostbyname3_r(
				name,
				AF_INET,
				host,
				buffer, buflen,
				errnop, h_errnop,
				NULL,
				NULL);
	return ret;
}
