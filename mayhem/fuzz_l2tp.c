// L2TP v2/v3 packet parser.
#include "harness_common.h"

void FreeL2TPPacket(L2TP_PACKET *p);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	UDPPACKET u;
	L2TP_PACKET *p;
	UCHAR *buf;

	if (size < 2)
	{
		return -1;
	}

	buf = Clone((void *)(data + 1), (UINT)(size - 1));

	Zero(&u, sizeof(u));
	u.Data = buf;
	u.Size = (UINT)(size - 1);
	u.SrcPort = (data[0] & 1) ? IPSEC_PORT_L2TPV3_VIRTUAL : IPSEC_PORT_L2TP;
	u.DestPort = IPSEC_PORT_L2TP;

	p = ParseL2TPPacket(&u);
	Free(buf);

	if (p == NULL)
	{
		return -1;
	}

	FreeL2TPPacket(p);

	return 0;
}
