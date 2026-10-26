// OpenVPN wire protocol (control/data packet framing): parse and re-build.
#include "harness_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	OPENVPN_PACKET *p;
	BUF *b;

	if (size == 0)
	{
		return -1;
	}

	p = OvsParsePacket((UCHAR *)data, (UINT)size);
	if (p == NULL)
	{
		return -1;
	}

	b = OvsBuildPacket(p);
	FreeBuf(b);
	OvsFreePacket(p);

	return 0;
}
