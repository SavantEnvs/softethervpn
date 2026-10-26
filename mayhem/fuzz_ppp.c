// PPP frame parser (LCP/PAP/CHAP/IPCP/IPv6CP/...): parse and re-build.
#include "harness_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	PPP_PACKET *p;
	BUF *b;

	if (size == 0)
	{
		return -1;
	}

	p = ParsePPPPacket((void *)data, (UINT)size);
	if (p == NULL)
	{
		return -1;
	}

	b = BuildPPPPacketData(p);
	FreeBuf(b);
	FreePPPPacket(p);

	return 0;
}
