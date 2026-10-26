// Known-answer probe for the oracle (mayhem/test.sh): drives the real mayaqua/cedar libraries with
// fixed inputs and prints one "KAT_OK <name>" / "KAT_FAIL <name>" line per check.
#define MAYHEM_NO_FUZZER_INIT
#include "harness_common.h"

#include <stdio.h>
#include <string.h>

static int g_fail = 0;
static int g_total = 0;

static void check(const char *name, bool ok)
{
	g_total++;
	if (ok)
	{
		printf("KAT_OK %s\n", name);
	}
	else
	{
		g_fail++;
		printf("KAT_FAIL %s\n", name);
	}
}

static void hex(char *dst, const UCHAR *src, UINT n)
{
	UINT i;
	for (i = 0; i < n; i++)
	{
		sprintf(dst + i * 2, "%02x", src[i]);
	}
}

static void kat_digest(void)
{
	UCHAR h[SHA1_SIZE];
	UCHAR m[MD5_SIZE];
	char s[128];

	Sha1(h, "abc", 3);
	hex(s, h, SHA1_SIZE);
	check("sha1-abc", strcmp(s, "a9993e364706816aba3e25717850c26c9cd0d89d") == 0);

	Md5(m, "abc", 3);
	hex(s, m, MD5_SIZE);
	check("md5-abc", strcmp(s, "900150983cd24fb0d6963f7d28e17f72") == 0);
}

static void kat_pack(void)
{
	PACK *p = NewPack();
	PACK *q;
	BUF *b;
	UCHAR d[3] = {1, 2, 3};
	UCHAR d2[3];
	char s[64];

	PackAddStr(p, "name", "hello");
	PackAddInt(p, "num", 0x01020304);
	PackAddData(p, "blob", d, sizeof(d));
	b = PackToBuf(p);

	// element count is the first big-endian UINT of the serialised pack
	check("pack-count", b->Size > 4 && READ_UINT(b->Buf) == 3);

	SeekBuf(b, 0, 0);
	q = BufToPack(b);
	check("pack-roundtrip", q != NULL);
	if (q != NULL)
	{
		check("pack-str", PackGetStr(q, "name", s, sizeof(s)) && strcmp(s, "hello") == 0);
		check("pack-int", PackGetInt(q, "num") == 0x01020304);
		check("pack-data", PackGetDataSize(q, "blob") == 3 && PackGetData(q, "blob", d2) && memcmp(d, d2, 3) == 0);
		FreePack(q);
	}
	FreeBuf(b);
	FreePack(p);
}

static void kat_packet(void)
{
	UCHAR f[14 + 20 + 8 + 4];
	PKT *p;
	IPV4_HEADER *ip;
	UDP_HEADER *udp;
	static const UCHAR mac_dst[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
	static const UCHAR mac_src[6] = {0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb};

	Zero(f, sizeof(f));
	Copy(f, mac_dst, 6);
	Copy(f + 6, mac_src, 6);
	f[12] = 0x08;
	f[13] = 0x00;
	ip = (IPV4_HEADER *)(f + 14);
	ip->VersionAndHeaderLength = 0x45;
	ip->TotalLength = Endian16(20 + 8 + 4);
	ip->TimeToLive = 64;
	ip->Protocol = IP_PROTO_UDP;
	ip->SrcIP = Endian32(0xC0A8010A);
	ip->DstIP = Endian32(0xC0A80114);
	ip->Checksum = IpChecksum(ip, 20);
	udp = (UDP_HEADER *)(f + 14 + 20);
	udp->SrcPort = Endian16(40000);
	udp->DstPort = Endian16(50000);
	udp->PacketLength = Endian16(8 + 4);
	Copy(f + 14 + 20 + 8, "ABCD", 4);

	p = ParsePacket(f, sizeof(f));
	check("packet-parsed", p != NULL);
	if (p != NULL)
	{
		check("packet-l3-ipv4", p->TypeL3 == L3_IPV4);
		check("packet-l4-udp", p->TypeL4 == L4_UDP);
		check("packet-ip-src", p->TypeL3 == L3_IPV4 && Endian32(p->L3.IPv4Header->SrcIP) == 0xC0A8010A);
		check("packet-udp-ports", p->TypeL4 == L4_UDP &&
			Endian16(p->L4.UDPHeader->SrcPort) == 40000 && Endian16(p->L4.UDPHeader->DstPort) == 50000);
		check("packet-mac-src", p->MacAddressSrc != NULL && memcmp(p->MacAddressSrc, mac_src, 6) == 0);
		FreePacket(p);
	}
}

static void kat_openvpn(void)
{
	static UCHAR pkt[] = {
		0x20,												// P_CONTROL_V1, key id 0
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,		// sender session id
		0x00,												// no ACKs
		0x00, 0x00, 0x00, 0x05,								// packet id
		'x', 'y', 'z'
	};
	OPENVPN_PACKET *p = OvsParsePacket(pkt, sizeof(pkt));

	check("openvpn-parsed", p != NULL);
	if (p != NULL)
	{
		check("openvpn-opcode", p->OpCode == OPENVPN_P_CONTROL_V1 && p->KeyId == 0);
		check("openvpn-session", p->MySessionId == 0x1122334455667788ULL);
		check("openvpn-packetid", p->PacketId == 5);
		check("openvpn-data", p->DataSize == 3 && memcmp(p->Data, "xyz", 3) == 0);
		OvsFreePacket(p);
	}
}

static void kat_ppp(void)
{
	static UCHAR pkt[] = {0xff, 0x03, 0xc0, 0x21, 0x01, 0x07, 0x00, 0x04};	// LCP Configure-Request, id 7
	PPP_PACKET *p = ParsePPPPacket(pkt, sizeof(pkt));

	check("ppp-parsed", p != NULL);
	if (p != NULL)
	{
		check("ppp-lcp", p->Protocol == 0xc021 && p->IsControl && p->Lcp != NULL &&
			p->Lcp->Code == 1 && p->Lcp->Id == 7);
		FreePPPPacket(p);
	}
}

static void kat_ike(void)
{
	static UCHAR pkt[28] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,		// initiator cookie
		0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,		// responder cookie
		0x00, 0x10, 0x02, 0x00,								// next payload, version, exchange type, flags
		0x00, 0x00, 0x00, 0x09,								// message id
		0x00, 0x00, 0x00, 0x1c								// length 28
	};
	IKE_PACKET *p = IkeParse(pkt, sizeof(pkt), NULL);

	check("ike-parsed", p != NULL);
	if (p != NULL)
	{
		check("ike-cookies", p->InitiatorCookie == 0x0102030405060708ULL && p->ResponderCookie == 0xa1a2a3a4a5a6a7a8ULL);
		check("ike-exchange", p->ExchangeType == 2 && p->MessageId == 9 && p->MessageSize == 28 && !p->FlagEncrypted);
		IkeFree(p);
	}
}

static void kat_sstp(void)
{
	static UCHAR pkt[] = {0x10, 0x01, 0x00, 0x08, 0x00, 0x04, 0x00, 0x00};	// control, message type 4, no attributes
	SSTP_PACKET *p = SstpParsePacket(pkt, sizeof(pkt));

	check("sstp-parsed", p != NULL);
	if (p != NULL)
	{
		check("sstp-control", p->IsControl && p->MessageType == 4 && p->DataSize == 4);
		SstpFreePacket(p);
	}
}

static void kat_cfg(void)
{
	char text[] = "declare root\n{\n\tuint Port 443\n\tstring Name hello\n}\n";
	BUF *b = NewBufFromMemory(text, (UINT)strlen(text));
	FOLDER *f = CfgBufTextToFolder(b);
	char s[64];

	check("cfg-parsed", f != NULL);
	if (f != NULL)
	{
		check("cfg-uint", CfgGetInt(f, "Port") == 443);
		check("cfg-str", CfgGetStr(f, "Name", s, sizeof(s)) && strcmp(s, "hello") == 0);
		CfgDeleteFolder(f);
	}
	FreeBuf(b);
}

static void kat_json(void)
{
	char text[] = "{\"port\": 443, \"name\": \"vpn\"}";
	JSON_VALUE *v = JsonParseString(text);

	check("json-parsed", v != NULL);
	if (v != NULL)
	{
		JSON_OBJECT *o = JsonValueGetObject(v);
		check("json-num", o != NULL && JsonGetNumber(o, "port") == 443);
		check("json-str", o != NULL && strcmp(JsonGetStr(o, "name"), "vpn") == 0);
		JsonFree(v);
	}
}

int main(int argc, char **argv)
{
	InitMayaqua(false, false, argc, argv);
	InitCedar();

	kat_digest();
	kat_pack();
	kat_packet();
	kat_openvpn();
	kat_ppp();
	kat_ike();
	kat_sstp();
	kat_cfg();
	kat_json();

	printf("KAT_SUMMARY total=%d failed=%d\n", g_total, g_fail);

	FreeCedar();
	FreeMayaqua();
	return g_fail == 0 ? 0 : 1;
}
