#include "Utils.h"
#include <hde/hde64.h>

/* https://github.com/weak1337/Alcatraz/blob/b4dd21594af6b00b49f94310eeb89002924dd741/Alcatraz/pe/pe.cpp#L80 */
LONG Utils::Align(LONG Address, LONG Alignment)
{
	return Address + (Alignment - (Address % Alignment));
}

/* Get function size by moving cursor until we hit the padding */
ULONG Utils::getFunctionSize(PVOID pFunction)
{
	hde64s hs;
	ULONG funcSize = 0;
	while (hde64_disasm((PVOID)((ULONG64)pFunction + funcSize), &hs) && !(hs.flags & F_ERROR))
		funcSize += hs.len;
		
	return funcSize;
}