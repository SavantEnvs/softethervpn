// OpenVPN over TCP: the 2-byte length framing that OvsProcessData splits into datagrams (the proto
// layer's ProcessData callback), then the OpenVPN server state machine over each datagram.
#include "harness_common.h"

static CEDAR *cedar;
static LIST *options;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	void *server = NULL;
	INTERRUPT_MANAGER *im;
	SOCK_EVENT *se;
	TCP_RAW_DATA *in;
	FIFO *out;
	IP src, dst;

	if (size == 0)
	{
		return -1;
	}

	if (cedar == NULL)
	{
		const PROTO_OPTION *opt;
		cedar = NewCedar(NULL, NULL);
		options = NewListFast(NULL);
		for (opt = OvsOptions(); opt->Name != NULL; ++opt)
		{
			Add(options, (void *)opt);
		}
	}

	im = NewInterruptManager();
	se = NewSockEvent();
	OvsInit(&server, options, cedar, im, se, "AES-128-CBC", "localhost");

	SetIP(&src, 192, 0, 2, 1);
	SetIP(&dst, 192, 0, 2, 2);
	in = NewTcpRawData(&src, 40000, &dst, 1194);
	out = NewFifoFast();

	WriteFifo(in->Data, (void *)data, (UINT)size);
	OvsProcessData(server, in, out);

	ReleaseFifo(out);
	FreeTcpRawData(in);
	OvsFree(server);
	FreeInterruptManager(im);
	ReleaseSockEvent(se);

	return 0;
}
