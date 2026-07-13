/*
 * Wire level regression test for the VRRP auth_hmac extension. The fixed
 * vectors are the draft appendix images, the single source of truth.
 * Build and run: make auth_hmac_test && ./auth_hmac_test
 *
 * Copyright (C) 2026 Alexandre Cassen, <acassen@gmail.com>
 */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/ip.h>

#include "vrrp.h"
#include "memory.h"

#define ARRAY_SIZE(x)	(sizeof(x) / sizeof((x)[0]))

#define MSG4_LEN	12			/* v3 header + one IPv4 VIP */
#define MSG6_LEN	24			/* v3 header + one IPv6 VIP */
#define ADV6_LEN	(MSG6_LEN + sizeof(vrrp_auth_ext_t))
#define TRAILER(field)	(MSG6_LEN + offsetof(vrrp_auth_ext_t, field))

static int fails;

static void
check(const char *what, int got, int expected)
{
	const char *names[] = { "OK", "MALFORMED", "UNKNOWN_KEY",
				"BAD_HMAC", "STALE", "REPLAY" };

	if (got == expected) {
		printf("PASS %s = %s\n", what, names[got]);
		return;
	}

	printf("FAIL %s = %s, expected %s\n", what, names[got], names[expected]);
	fails++;
}

static void
expect(const char *what, bool ok)
{
	printf("%s %s\n", ok ? "PASS" : "FAIL", what);
	fails += !ok;
}

static void
hex2bin(const char *hex, uint8_t *out, size_t len)
{
	static const char digits[] = "0123456789abcdef";

	while (len--) {
		*out = (uint8_t)((strchr(digits, *hex++) - digits) << 4);
		*out++ |= (uint8_t)(strchr(digits, *hex++) - digits);
	}
}

/* standard internet checksum with accumulation */
static uint32_t
csum_add(uint32_t acc, const uint8_t *buf, size_t len)
{
	while (len > 1) {
		acc += (uint32_t)(buf[0] << 8 | buf[1]);
		buf += 2;
		len -= 2;
	}
	if (len)
		acc += (uint32_t)(buf[0] << 8);

	return acc;
}

static uint16_t
csum_fold(uint32_t acc)
{
	while (acc >> 16)
		acc = (acc & 0xffff) + (acc >> 16);

	return (uint16_t)~acc;
}

/*
 * What the kernel does on rawv6 output with IPV6_CHECKSUM offset 6: transport
 * checksum with the IPv6 pseudo header over the whole payload, trailer included.
 */
static uint16_t
ipv6_transport_csum(const struct in6_addr *src, const struct in6_addr *dst,
		    const uint8_t *payload, size_t len)
{
	uint8_t ph[40];
	uint32_t acc;

	memset(ph, 0, sizeof(ph));
	memcpy(ph, src, 16);
	memcpy(ph + 16, dst, 16);
	ph[34] = (uint8_t)(len >> 8);
	ph[35] = (uint8_t)len;
	ph[39] = IPPROTO_VRRP;

	acc = csum_add(0, ph, sizeof(ph));
	acc = csum_add(acc, payload, len);

	return csum_fold(acc);
}

static vrrp_auth_hmac_t *
make_ah(void)
{
	static const uint8_t key[32] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
	};
	vrrp_auth_hmac_t *ah;

	PMALLOC(ah);
	INIT_LIST_HEAD(&ah->keys);
	ah->ext_type = VRRP_AUTH_HMAC_TYPE_SHA256;
	ah->active_key = 1;
	ah->mode = VRRP_AUTH_HMAC_ENFORCE;
	ah->anti_replay_time = true;
	ah->time_window = 5;
	vrrp_auth_hmac_add_key(ah, 1, key, sizeof(key));

	return ah;
}

static void
make_vrrp(vrrp_t *v, int family, uint8_t vrid, const char *src)
{
	memset(v, 0, sizeof(*v));
	v->family = family;
	v->version = 3;
	v->vrid = vrid;
	if (family == AF_INET6) {
		v->saddr.in6.sin6_family = AF_INET6;
		inet_pton(AF_INET6, src, &v->saddr.in6.sin6_addr);
	} else {
		v->saddr.in.sin_family = AF_INET;
		inet_pton(AF_INET, src, &v->saddr.in.sin_addr);
	}
	v->pkt_saddr = v->saddr;
	v->auth_hmac = make_ah();
}

/* VRRPv3 advert: 8 byte header, chksum at offset 6, then the VIP list */
static void
build_advert(uint8_t *hd, uint8_t vrid, uint8_t prio, uint8_t naddr)
{
	memset(hd, 0, 8);
	hd[0] = 0x31;			/* version 3, advertisement */
	hd[1] = vrid;
	hd[2] = prio;
	hd[3] = naddr;
	hd[5] = 100;			/* max advert int, 1s in centisec */
}

/* The IPv6 advert of the appendix vector, in place and ready to sign */
static vrrp_auth_ext_t *
make_advert6(vrrp_t *v, uint8_t *pkt)
{
	memset(pkt, 0, ADV6_LEN);
	build_advert(pkt, 51, 200, 1);
	inet_pton(AF_INET6, "fe80::100", pkt + sizeof(vrrphdr_t));
	make_vrrp(v, AF_INET6, 51, "fe80::10");
	v->send_buffer = (char *)pkt;
	v->send_buffer_size = ADV6_LEN;

	return PTR_CAST(vrrp_auth_ext_t, pkt + MSG6_LEN);
}

/* Verify one image, a NULL replay state means a fresh receiver */
static int
verify(vrrp_t *v, const uint8_t *pdu, size_t mlen, vrrp_replay_state_t *st)
{
	vrrp_replay_state_t fresh = {};
	int skew;

	return vrrp_auth_hmac_check(v, pdu, mlen,
				    PTR_CAST_CONST(vrrp_auth_ext_t, pdu + mlen),
				    st ? st : &fresh, &skew);
}

/*
 * Draft appendix wire images, key 00..1f, VRID 51, prio 200, sequence
 * 0x6800000080000000. IPv4: src 198.51.100.10, VIP 192.0.2.100, RFC 9568
 * message-only checksum. IPv6: src fe80::10, VIP fe80::100, transport
 * checksum for destination fe80::20 covering the trailer.
 */
static const char ipv4_vec[] =
	"3133c80100644402c0000264"
	"010100006800000080000000"
	"1b84bc4e8e43892dc6d98448f8ee2265";
static const char ipv6_vec[] =
	"3133c8010064a2e9"
	"fe800000000000000000000000000100"
	"010100006800000080000000"
	"c8c56146ebfd66ee10ec4d8186461b78";

static const struct {
	const char *what;
	const char *hex;
	int family;
	uint8_t vrid;
	const char *src;
	size_t mlen;
} vectors[] = {
	{ "ipv4 appendix vector", ipv4_vec, AF_INET,  51, "198.51.100.10", MSG4_LEN },
	{ "ipv6 appendix vector", ipv6_vec, AF_INET6, 51, "fe80::10",	   MSG6_LEN },
};

/* one flipped byte per case against the IPv6 appendix image */
static const struct {
	const char *what;
	size_t off;
	int expected;
} mutations[] = {
	{ "tampered priority",	     offsetof(vrrphdr_t, priority),	VRRP_AUTH_HMAC_BAD_HMAC },
	{ "tampered advert interval", offsetof(vrrphdr_t, v3.adver_int), VRRP_AUTH_HMAC_BAD_HMAC },
	{ "tampered checksum",	     offsetof(vrrphdr_t, chksum),	VRRP_AUTH_HMAC_OK },
	{ "tampered vip",	     sizeof(vrrphdr_t) + 15,		VRRP_AUTH_HMAC_BAD_HMAC },
	{ "unsupported ext type",    TRAILER(ext_type),			VRRP_AUTH_HMAC_MALFORMED },
	{ "unknown key id",	     TRAILER(key_id),			VRRP_AUTH_HMAC_UNKNOWN_KEY },
	{ "nonzero reserved",	     TRAILER(reserved),			VRRP_AUTH_HMAC_MALFORMED },
	{ "tampered seconds",	     TRAILER(sec),			VRRP_AUTH_HMAC_BAD_HMAC },
	{ "tampered counter",	     TRAILER(ctr),			VRRP_AUTH_HMAC_BAD_HMAC },
	{ "tampered hmac",	     TRAILER(hmac),			VRRP_AUTH_HMAC_BAD_HMAC },
};

static void
test_vectors(void)
{
	uint8_t img[ADV6_LEN], buf[ADV6_LEN];
	vrrp_t v;
	unsigned i;

	/* the fixed timestamps lie outside any live window, use monotonic */
	for (i = 0; i < ARRAY_SIZE(vectors); i++) {
		hex2bin(vectors[i].hex, img, vectors[i].mlen + sizeof(vrrp_auth_ext_t));
		make_vrrp(&v, vectors[i].family, vectors[i].vrid, vectors[i].src);
		v.auth_hmac->anti_replay_time = false;
		check(vectors[i].what, verify(&v, img, vectors[i].mlen, NULL),
		      VRRP_AUTH_HMAC_OK);
	}

	hex2bin(ipv6_vec, img, sizeof(img));
	make_vrrp(&v, AF_INET6, 51, "fe80::10");
	v.auth_hmac->anti_replay_time = false;
	for (i = 0; i < ARRAY_SIZE(mutations); i++) {
		memcpy(buf, img, sizeof(img));
		buf[mutations[i].off] ^= 0x01;
		check(mutations[i].what, verify(&v, buf, MSG6_LEN, NULL),
		      mutations[i].expected);
	}

	/* the pseudo header binds the source address and the vrid */
	inet_pton(AF_INET6, "fe80::20", &v.pkt_saddr.in6.sin6_addr);
	check("wrong source address", verify(&v, img, MSG6_LEN, NULL),
	      VRRP_AUTH_HMAC_BAD_HMAC);
	inet_pton(AF_INET6, "fe80::10", &v.pkt_saddr.in6.sin6_addr);
	v.vrid = 52;
	check("wrong vrid", verify(&v, img, MSG6_LEN, NULL),
	      VRRP_AUTH_HMAC_BAD_HMAC);
}

static void
test_ipv4(void)
{
	/* ip header + vrrp header + one VIP + trailer */
	uint8_t pkt[20 + MSG4_LEN + sizeof(vrrp_auth_ext_t)];
	uint8_t *hd = pkt + 20;
	vrrp_replay_state_t st = {};
	vrrp_t v;
	uint16_t csum;

	memset(pkt, 0, sizeof(pkt));
	build_advert(hd, 51, 200, 1);
	inet_pton(AF_INET, "192.0.2.100", hd + sizeof(vrrphdr_t));

	/* RFC 9568 IPv4 checksum over the message only, no pseudo header */
	csum = csum_fold(csum_add(0, hd, MSG4_LEN));
	hd[6] = (uint8_t)(csum >> 8);
	hd[7] = (uint8_t)csum;

	make_vrrp(&v, AF_INET, 51, "198.51.100.10");
	v.send_buffer = (char *)pkt;
	v.send_buffer_size = sizeof(pkt);

	/* transmit order of vrrp.c: checksum at build time, sign at send time */
	vrrp_auth_hmac_sign(&v);

	check("ipv4 wire image", verify(&v, hd, MSG4_LEN, &st), VRRP_AUTH_HMAC_OK);
}

static void
test_ipv6(void)
{
	uint8_t pkt[ADV6_LEN], save[ADV6_LEN];
	vrrp_replay_state_t st = {}, st2 = {};
	struct in6_addr dst;
	vrrp_t v;
	uint16_t csum;

	make_advert6(&v, pkt);
	inet_pton(AF_INET6, "fe80::20", &dst);

	/* transmit order of vrrp.c: chksum 0, sign, then the kernel checksum */
	vrrp_auth_hmac_sign(&v);
	csum = ipv6_transport_csum(&v.saddr.in6.sin6_addr, &dst, pkt, sizeof(pkt));
	pkt[6] = (uint8_t)(csum >> 8);
	pkt[7] = (uint8_t)csum;

	check("ipv6 wire image", verify(&v, pkt, MSG6_LEN, &st), VRRP_AUTH_HMAC_OK);
	check("ipv6 replayed wire image", verify(&v, pkt, MSG6_LEN, &st),
	      VRRP_AUTH_HMAC_REPLAY);

	/* one signed advert replicates unchanged to every peer */
	check("ipv6 same copy at a second peer", verify(&v, pkt, MSG6_LEN, &st2),
	      VRRP_AUTH_HMAC_OK);

	/* receive-only sends no trailer and leaves the buffer untouched */
	v.auth_hmac->mode = VRRP_AUTH_HMAC_RECEIVE_ONLY;
	expect("receive-only trailer length = 0", !vrrp_auth_hmac_trailer_len(&v));
	memcpy(save, pkt, sizeof(pkt));
	vrrp_auth_hmac_sign(&v);
	expect("receive-only sign left the buffer untouched",
	       !memcmp(save, pkt, sizeof(pkt)));
}

static void
test_window(void)
{
	uint8_t pkt[ADV6_LEN];
	vrrp_auth_ext_t *tr;
	vrrp_t v;

	tr = make_advert6(&v, pkt);
	vrrp_auth_hmac_sign(&v);

	/* the freshness window sheds a stale stamp before the digest */
	tr->sec = htonl((uint32_t)time(NULL) - 100);
	check("stale timestamp", verify(&v, pkt, MSG6_LEN, NULL),
	      VRRP_AUTH_HMAC_STALE);
	tr->sec = htonl((uint32_t)time(NULL) + 100);
	check("future timestamp", verify(&v, pkt, MSG6_LEN, NULL),
	      VRRP_AUTH_HMAC_STALE);
}

static void
test_sequence(void)
{
	uint8_t pkt[ADV6_LEN];
	vrrp_replay_state_t st = {};
	vrrp_auth_ext_t *tr;
	vrrp_t v;
	uint32_t now;
	int32_t d;

	tr = make_advert6(&v, pkt);

	/* time mode resets a stranded future timestamp to the clock */
	v.auth_hmac->send_seq = ((uint64_t)((uint32_t)time(NULL) + 3600)) << 32;
	vrrp_auth_hmac_sign(&v);
	now = (uint32_t)time(NULL);
	d = (int32_t)(ntohl(tr->sec) - now);
	expect("clock step reset", d >= -1 && d <= 1);

	/* a receiver mark stranded past the window expires */
	st.valid = true;
	st.seq = ((uint64_t)(now + 3600)) << 32;
	check("expired future mark", verify(&v, pkt, MSG6_LEN, &st),
	      VRRP_AUTH_HMAC_OK);
	check("replay after expiry", verify(&v, pkt, MSG6_LEN, &st),
	      VRRP_AUTH_HMAC_REPLAY);

	/* monotonic mode keeps strict growth and keeps its mark */
	v.auth_hmac->anti_replay_time = false;
	now = (uint32_t)time(NULL);
	v.auth_hmac->send_seq = ((uint64_t)(now + 3600)) << 32;
	vrrp_auth_hmac_sign(&v);
	expect("monotonic keeps growth",
	       ntohl(tr->sec) == now + 3600 && ntohs(tr->ctr) == 1);
	st.valid = true;
	st.seq = ((uint64_t)(now + 7200)) << 32;
	check("monotonic keeps its mark", verify(&v, pkt, MSG6_LEN, &st),
	      VRRP_AUTH_HMAC_REPLAY);
}

int
main(void)
{
	test_vectors();
	test_ipv4();
	test_ipv6();
	test_window();
	test_sequence();

	printf("%s\n", fails ? "FAILURES" : "all tests passed");

	return fails;
}
