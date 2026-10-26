// Config file reader (text and binary forms) used for vpn_server.config and friends.
#include "harness_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	BUF *in;
	FOLDER *f;
	BUF *out;

	if (size < 2)
	{
		return -1;
	}

	in = NewBufFromMemory((void *)(data + 1), (UINT)(size - 1));

	if (data[0] & 1)
	{
		f = CfgBufBinToFolder(in);
	}
	else
	{
		f = CfgBufTextToFolder(in);
	}
	FreeBuf(in);

	if (f == NULL)
	{
		return -1;
	}

	out = CfgFolderToBuf(f, (data[0] & 2) != 0);
	FreeBuf(out);
	CfgDeleteFolder(f);

	return 0;
}
