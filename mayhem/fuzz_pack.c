// PACK (the binary key/value container of the whole SoftEther protocol): parse, walk, re-serialise.
#include "harness_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	BUF *in;
	BUF *out;
	PACK *p;
	PACK *p2;
	UINT i;

	if (size == 0)
	{
		return -1;
	}

	in = NewBufFromMemory((void *)data, (UINT)size);
	p = BufToPack(in);
	FreeBuf(in);

	if (p == NULL)
	{
		return -1;
	}

	for (i = 0; i < LIST_NUM(p->elements); i++)
	{
		ELEMENT *e = LIST_DATA(p->elements, i);
		UINT j;

		for (j = 0; j < e->num_value; j++)
		{
			switch (e->type)
			{
			case VALUE_INT:
				(void)GetIntValue(e, j);
				break;
			case VALUE_INT64:
				(void)GetInt64Value(e, j);
				break;
			case VALUE_STR:
				(void)StrLen(GetStrValue(e, j));
				break;
			case VALUE_UNISTR:
				(void)UniStrLen(GetUniStrValue(e, j));
				break;
			case VALUE_DATA:
				if (GetDataValueSize(e, j) != 0)
				{
					volatile UCHAR c = ((UCHAR *)GetDataValue(e, j))[GetDataValueSize(e, j) - 1];
					(void)c;
				}
				break;
			}
		}
	}

	out = PackToBuf(p);
	p2 = BufToPack(out);
	FreeBuf(out);
	FreePack(p2);
	FreePack(p);

	return 0;
}
