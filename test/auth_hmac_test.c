/*
 * Wire level regression test for the VRRP auth_hmac extension.
 * Build and run: make auth_hmac_test && ./auth_hmac_test
 */
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>

#include "vrrp.h"
#include "memory.h"

#define IPPROTO_VRRP_N	112

static int fails;

static void
check(const char *what, int got, int expect)
{
	const char *names[] = { "OK", "MALFORMED", "UNKNOWN_KEY",
				"BAD_HMAC", "STALE", "REPLAY" };

	if (got == expect) {
		printf("PASS %s = %s\n", what, names[got]);
		return;
	}

	printf("FAIL %s = %s, expected %s\n", what, names[got], names[expect]);
	fails++;
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
	ph[39] = IPPROTO_VRRP_N;

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

static void
test_ipv6(void)
{
	/* header + one IPv6 VIP + trailer */
	uint8_t pkt[8 + 16 + sizeof(vrrp_auth_ext_t)];
	uint8_t save[sizeof(pkt)];
	struct in6_addr src, dst, vip;
	vrrp_auth_ext_t *tr = PTR_CAST(vrrp_auth_ext_t, pkt + 8 + 16);
	vrrp_replay_state_t st = {0};
	vrrp_t v = {0};
	uint16_t csum;
	int skew;

	inet_pton(AF_INET6, "fd00::1", &src);
	inet_pton(AF_INET6, "fd00::2", &dst);
	inet_pton(AF_INET6, "fd00::100", &vip);

	build_advert(pkt, 51, 200, 1);
	memcpy(pkt + 8, &vip, 16);

	v.family = AF_INET6;
	v.version = 3;
	v.vrid = 51;
	v.saddr.in6.sin6_family = AF_INET6;
	v.saddr.in6.sin6_addr = src;
	v.pkt_saddr = v.saddr;
	v.send_buffer = (char *)pkt;
	v.send_buffer_size = sizeof(pkt);
	v.auth_hmac = make_ah();

	/* transmit order of vrrp.c: chksum 0, sign, then the kernel checksum */
	vrrp_auth_hmac_sign(&v);
	csum = ipv6_transport_csum(&src, &dst, pkt, sizeof(pkt));
	pkt[6] = (uint8_t)(csum >> 8);
	pkt[7] = (uint8_t)csum;

	check("ipv6 wire image",
	      vrrp_auth_hmac_check(&v, pkt, 8 + 16, tr, &st, &skew),
	      VRRP_AUTH_HMAC_OK);

	check("ipv6 replayed wire image",
	      vrrp_auth_hmac_check(&v, pkt, 8 + 16, tr, &st, &skew),
	      VRRP_AUTH_HMAC_REPLAY);

	pkt[2] ^= 0x80;			/* tamper with the priority */
	check("ipv6 tampered priority",
	      vrrp_auth_hmac_check(&v, pkt, 8 + 16, tr, &st, &skew),
	      VRRP_AUTH_HMAC_BAD_HMAC);
	pkt[2] ^= 0x80;

	/* receive-only sends no trailer and leaves the buffer untouched */
	v.auth_hmac->mode = VRRP_AUTH_HMAC_RECEIVE_ONLY;
	if (vrrp_auth_hmac_trailer_len(&v)) {
		printf("FAIL receive-only trailer length not zero\n");
		fails++;
	} else
		printf("PASS receive-only trailer length = 0\n");
	memcpy(save, pkt, sizeof(pkt));
	vrrp_auth_hmac_sign(&v);
	if (memcmp(save, pkt, sizeof(pkt))) {
		printf("FAIL receive-only sign modified the buffer\n");
		fails++;
	} else
		printf("PASS receive-only sign left the buffer untouched\n");
}

static void
test_ipv4(void)
{
	/* ip header + vrrp header + one VIP + trailer */
	uint8_t pkt[20 + 8 + 4 + sizeof(vrrp_auth_ext_t)];
	uint8_t *hd = pkt + 20;
	uint8_t ph[12];
	vrrp_auth_ext_t *tr = PTR_CAST(vrrp_auth_ext_t, pkt + 20 + 8 + 4);
	vrrp_replay_state_t st = {0};
	vrrp_t v = {0};
	struct in_addr src, dst, vip;
	uint32_t acc;
	uint16_t csum;
	int skew;

	inet_pton(AF_INET, "192.168.77.1", &src);
	inet_pton(AF_INET, "192.168.77.2", &dst);
	inet_pton(AF_INET, "192.168.77.100", &vip);

	memset(pkt, 0, sizeof(pkt));
	build_advert(hd, 52, 200, 1);
	memcpy(hd + 8, &vip, 4);

	/* VRRPv3 IPv4 checksum over pseudo header and message, trailer excluded */
	memset(ph, 0, sizeof(ph));
	memcpy(ph, &src, 4);
	memcpy(ph + 4, &dst, 4);
	ph[9] = IPPROTO_VRRP_N;
	ph[11] = 8 + 4;
	acc = csum_add(0, ph, sizeof(ph));
	acc = csum_add(acc, hd, 8 + 4);
	csum = csum_fold(acc);
	hd[6] = (uint8_t)(csum >> 8);
	hd[7] = (uint8_t)csum;

	v.family = AF_INET;
	v.version = 3;
	v.vrid = 52;
	v.saddr.in.sin_family = AF_INET;
	v.saddr.in.sin_addr = src;
	v.pkt_saddr = v.saddr;
	v.send_buffer = (char *)pkt;
	v.send_buffer_size = sizeof(pkt);
	v.auth_hmac = make_ah();

	/* transmit order of vrrp.c: checksum at build time, sign at send time */
	vrrp_auth_hmac_sign(&v);

	check("ipv4 wire image",
	      vrrp_auth_hmac_check(&v, hd, 8 + 4, tr, &st, &skew),
	      VRRP_AUTH_HMAC_OK);
}

int
main(void)
{
	test_ipv4();
	test_ipv6();

	printf("%s\n", fails ? "FAILURES" : "all tests passed");

	return fails;
}
