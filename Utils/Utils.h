#ifndef H_UTILS
#define H_UTILS

#include <Windows.h>

namespace Utils
{
	LONG Align(LONG Offset, LONG Alignment);
	ULONG getFunctionSize(PVOID pFunction);
}


#endif