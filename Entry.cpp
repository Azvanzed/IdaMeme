#include <Windows.h>
#include <winternl.h>
#include <fstream>
#include <vector>	
#include <intrin.h>

#include "Utils/Utils.h"

constexpr ULONG NSA_SIZE = 0x20000; // omega magic number

__declspec(safebuffers) LONG cEntryStart(LONG Argc, CHAR* Argv[])
{
	/* Getting the EP offset from the PE Header  */
	PEB* pPeb = (PEB*)__readgsqword(0x60);
	ULONG64 imageBase = *(ULONG64*)((ULONG64)pPeb + 0x10);

	IMAGE_DOS_HEADER* pDos = (IMAGE_DOS_HEADER*)imageBase;
	IMAGE_NT_HEADERS* pNt = (IMAGE_NT_HEADERS*)(imageBase + pDos->e_lfanew);

	// We white mans save the EP offset inside the Checksum
	return ((decltype(&cEntryStart))(imageBase + pNt->OptionalHeader.CheckSum))(Argc, Argv);
}

LONG main(LONG Argc, CHAR* Argv[])
{
	/* Loading file to memory */
	std::vector<BYTE> fileData;
	std::ifstream inputFile(Argv[1], std::ios::binary);
	fileData.assign((std::istreambuf_iterator<CHAR>(inputFile)), std::istreambuf_iterator<CHAR>());
	inputFile.close();

	/* PE header white stuff */
	ULONG64					imageBase = (ULONG64)fileData.data();
	IMAGE_DOS_HEADER*		pDos = (IMAGE_DOS_HEADER*)imageBase;
	IMAGE_NT_HEADERS*		pNt = (IMAGE_NT_HEADERS*)(imageBase + pDos->e_lfanew);






	/* Credits to weak1337 https://github.com/weak1337/Alcatraz/blob/b4dd21594af6b00b49f94310eeb89002924dd741/Alcatraz/pe/pe.cpp#L85 */
	IMAGE_SECTION_HEADER* pFirstSection = IMAGE_FIRST_SECTION(pNt);
	IMAGE_SECTION_HEADER* pLastSection	= &pFirstSection[pNt->FileHeader.NumberOfSections - 1];

	IMAGE_SECTION_HEADER* pNewSection = (IMAGE_SECTION_HEADER*)((ULONG64)&pLastSection->Characteristics + 4);
	memset(pNewSection, 0, sizeof(IMAGE_SECTION_HEADER));

	strcpy((CHAR*)pNewSection->Name, ".nsa");
	pNewSection->Misc.VirtualSize = Utils::Align(NSA_SIZE + sizeof(ULONG) + 1, pNt->OptionalHeader.SectionAlignment);
	pNewSection->VirtualAddress = Utils::Align(pLastSection->VirtualAddress + pLastSection->Misc.VirtualSize, pNt->OptionalHeader.SectionAlignment);
	pNewSection->SizeOfRawData = Utils::Align(NSA_SIZE + sizeof(ULONG) + 1, pNt->OptionalHeader.FileAlignment);
	pNewSection->PointerToRawData = Utils::Align(pLastSection->PointerToRawData + pLastSection->SizeOfRawData, pNt->OptionalHeader.FileAlignment);
	pNewSection->Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE;
	++pNt->FileHeader.NumberOfSections;

	ULONG oldFileSize = pNt->OptionalHeader.SizeOfImage;
	pNt->OptionalHeader.SizeOfImage = Utils::Align(pNt->OptionalHeader.SizeOfImage + NSA_SIZE + sizeof(ULONG) + 1 + sizeof(IMAGE_SECTION_HEADER), pNt->OptionalHeader.SectionAlignment);
	pNt->OptionalHeader.SizeOfHeaders = Utils::Align(pNt->OptionalHeader.SizeOfHeaders + sizeof(IMAGE_SECTION_HEADER), pNt->OptionalHeader.FileAlignment);

	std::vector<BYTE> newBuffer;
	newBuffer.resize(pNt->OptionalHeader.SizeOfImage);
	memset(newBuffer.data(), 0, pNt->OptionalHeader.SizeOfImage);
	memcpy(newBuffer.data(), fileData.data(), oldFileSize);
	fileData = newBuffer;

	/* std::vector resize relocates the heap alloc which is not white so we set the new image base */
	imageBase = (ULONG64)fileData.data();
	pDos = (IMAGE_DOS_HEADER*)imageBase;
	pNt = (IMAGE_NT_HEADERS*)(imageBase + pDos->e_lfanew);







	/* Setup payload, and custom entry point */
	LONG cEntrySize = Utils::getFunctionSize(&cEntryStart);
	memset((PVOID)(imageBase + pNewSection->PointerToRawData), 0, pNewSection->SizeOfRawData);
	memcpy((PVOID)(imageBase + pNewSection->PointerToRawData), &cEntryStart, cEntrySize);
	
	BYTE jmpBack[5] =
	{
		0xE9, 0x00, 0x00, 0x00, 0x00	// jmp rel32
	};

	/* Jump to the custom entry point */
	*(LONG*)&jmpBack[1] = -cEntrySize;
	memcpy((PVOID)(imageBase + pNewSection->PointerToRawData + cEntrySize), &jmpBack, sizeof(jmpBack));

	/* Chained jumps until it reaches the jump that jumps to the custom entry point */
	CONST ULONG jmpCount = 20000; // magic numbo v2
	for (ULONG i = 0; i < jmpCount; ++i)
	{
		*(LONG*)&jmpBack[1] = (sizeof(jmpBack) * 2) * -1;
		memcpy((PVOID)(imageBase + pNewSection->PointerToRawData + cEntrySize + (sizeof(jmpBack) * (i + 1))), &jmpBack, sizeof(jmpBack));
	}
	
	/* Set the original EP and modify the EP to point to our stub */
	pNt->OptionalHeader.CheckSum			= pNt->OptionalHeader.AddressOfEntryPoint;
	pNt->OptionalHeader.AddressOfEntryPoint = pNewSection->VirtualAddress + cEntrySize + (sizeof(jmpBack) * (jmpCount - 1));

	/* Write the ultimate memer file */
	std::ofstream outputFile("Memer.exe", std::ios::binary);
	outputFile.write((CHAR*)fileData.data(), fileData.size());
	outputFile.close();
	return 0;
}