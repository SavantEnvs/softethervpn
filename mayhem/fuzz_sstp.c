// SSTP packet + attribute parser: parse and re-build.
#include "harness_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	SSTP_PACKET *p;
	BUF *b;

	if (size == 0)
	{
		return -1;
	}

	p = SstpParsePacket((UCHAR *)data, (UINT)size);
	if (p == NULL)
	{
		return -1;
	}

	b = SstpBuildPacket(p);
	FreeBuf(b);
	SstpFreePacket(p);

	return 0;
}
