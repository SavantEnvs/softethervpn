// Ethernet frame parser used by the virtual L2/L3 stack (ARP/IPv4/IPv6/TCP/UDP/ICMP/DHCP/DNS/...).
#include "harness_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	UCHAR *buf;
	PKT *p;
	UCHAR mode;

	if (size < 2)
	{
		return -1;
	}

	mode = data[0];
	data++;
	size--;

	buf = Clone((void *)data, (UINT)size);

	p = ParsePacketEx5(buf, (UINT)size,
		(mode & 0x01) != 0,
		(mode & 0x02) ? 0x9100 : 0x8100,
		(mode & 0x04) != 0,
		(mode & 0x08) != 0,
		(mode & 0x10) != 0,
		(mode & 0x20) != 0);

	if (p != NULL)
	{
		FreePacket(p);
	}
	Free(buf);

	if (p == NULL)
	{
		return -1;
	}

	return 0;
}
