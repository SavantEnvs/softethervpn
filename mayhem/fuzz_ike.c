// IKE/ISAKMP (IPsec) packet and payload parser, plaintext path.
#include "harness_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	IKE_PACKET *p;

	if (size < 2)
	{
		return -1;
	}

	p = IkeParseEx((void *)(data + 1), (UINT)(size - 1), NULL, (data[0] & 1) != 0);
	if (p == NULL)
	{
		return -1;
	}

	IkeFree(p);

	return 0;
}
