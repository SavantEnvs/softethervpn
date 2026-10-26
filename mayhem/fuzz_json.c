// JSON parser (parson) used by the JSON-RPC admin API: parse, serialise, compare.
#include "harness_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char *s;
	JSON_VALUE *v;
	char *out;

	if (size == 0)
	{
		return -1;
	}

	s = Malloc((UINT)size + 1);
	Copy(s, data + 0, (UINT)size);
	s[size] = 0;

	v = JsonParseString(s);
	Free(s);

	if (v == NULL)
	{
		return -1;
	}

	out = JsonToStr(v);
	JsonFreeString(out);
	JsonFree(v);

	return 0;
}
