#include "Windows.h"
#include <iostream>
#include <stdio.h>
#include <conio.h> 
#include <signal.h>

const int MAX_OPTIONS = 7;
const int MAX_FILEPATH_LENGTH = 255;
char filename[MAX_FILEPATH_LENGTH] = { 0 };

HANDLE file = NULL;
DWORD fileSize = NULL;
DWORD bytesRead = NULL;
LPVOID fileData = NULL;

PIMAGE_SECTION_HEADER sectionHeader = NULL;

IMAGE_IMPORT_DESCRIPTOR* importDescriptor = NULL;
PIMAGE_THUNK_DATA thunkData = NULL;
DWORD thunk = NULL;
DWORD rawOffset = NULL;

HANDLE hConsole = NULL;
WORD attributes = 0;

bool is64bit = false;

enum OPTIONS {
	DOS_HEADER = 1,
	NT_HEADER = 2,
	FILE_HEADER = 3,
	OPTIONAL_HEADER = 4,
	DIRECTORY_ADDRESS = 5,
	SECTIONS = 6,
	IMPORTS = 7,
	EXIT = 8
};


void sigfun(int sig)
{
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), attributes);
	exit(-10);
}

void flushStdin(void) {
	int ch;
	while (((ch = getchar()) != '\n') && (ch != EOF));
}

void printMenuHeader() {

	SetConsoleTextAttribute(hConsole,
		FOREGROUND_BLUE | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
	printf("-------------------------------------------------------------------------\n");
	printf("|  ____    ____        ____                        __                   |\n");
	printf("| /\\  _`\\ /\\  _`\\     /\\  _`\\                     /\\ \\                  |\n");
	printf("| \\ \\ \\L\\ \\ \\ \\L\\_\\   \\ \\ \\L\\ \\     __     __     \\_\\ \\     __   _ __   |\n");
	printf("|  \\ \\ ,__/\\ \\  _\\L    \\ \\ ,  /   /'__`\\ /'__`\\   /'_` \\  /'__`\\/\\`'__\\ |\n");
	printf("|   \\ \\ \\/  \\ \\ \\L\\ \\   \\ \\ \\\\ \\ /\\  __//\\ \\L\\.\\_/\\ \\L\\ \\/\\  __/\\ \\ \\/  |\n");
	printf("|    \\ \\_\\   \\ \\____/    \\ \\_\\ \\_\\ \\____\\ \\__/.\\_\\ \\___,_\\ \\____\\\\ \\_\\  |\n");
	printf("|     \\/_/    \\/___/      \\/_/\\/ /\\/____/\\/__/\\/_/\\/__,_ /\\/____/ \\/_/  |\n");
	printf("-------------------------------------------------------------------------\n");
	printf(" by: RudeNetworks.com | version: 0.2 beta\n");

	SetConsoleTextAttribute(hConsole,
		FOREGROUND_GREEN);

	printf("\n");
	printf(" File: %s Loaded!\n", filename);

	if (is64bit) {
		printf(" Architecture: 64bit \n");
	}
	else {
		printf(" Architecture: 32bit \n");
	}

	
	printf(" Size: %d bytes\n", fileSize);
}

int printOptions() {

	SetConsoleTextAttribute(hConsole,
		FOREGROUND_BLUE | FOREGROUND_BLUE | FOREGROUND_INTENSITY);

	printf("\n");
	printf(" Please Select Option:\n");
	printf("\n");
	printf(" 1. DOS Header\n");
	printf(" 2. NT Header\n");
	printf(" 3. File Header\n");
	printf(" 4. Optional Header\n");
	printf(" 5. Directory Address\n");
	printf(" 6. Sections\n");
	printf(" 7. Imports\n");
	printf(" 8. Exit \n");
	printf(" #: ");

	int val = -1;
	scanf_s("%d", &val);
	flushStdin();
	return val;
}

void printDosHeader(PIMAGE_DOS_HEADER dosHeader) {

	printf("-- PE DOS HEADER --------------------------------------------------------\n");
	printf("\t0x%x\t\tMagic number\n", dosHeader->e_magic);
	printf("\t0x%x\t\tBytes on last page of file\n", dosHeader->e_cblp);
	printf("\t0x%x\t\tPages in file\n", dosHeader->e_cp);
	printf("\t0x%x\t\tRelocations\n", dosHeader->e_crlc);
	printf("\t0x%x\t\tSize of header in paragraphs\n", dosHeader->e_cparhdr);
	printf("\t0x%x\t\tMinimum extra paragraphs needed\n", dosHeader->e_minalloc);
	printf("\t0x%x\t\tMaximum extra paragraphs needed\n", dosHeader->e_maxalloc);
	printf("\t0x%x\t\tInitial (relative) SS value\n", dosHeader->e_ss);
	printf("\t0x%x\t\tInitial SP value\n", dosHeader->e_sp);
	printf("\t0x%x\t\tInitial SP value\n", dosHeader->e_sp);
	printf("\t0x%x\t\tChecksum\n", dosHeader->e_csum);
	printf("\t0x%x\t\tInitial IP value\n", dosHeader->e_ip);
	printf("\t0x%x\t\tInitial (relative) CS value\n", dosHeader->e_cs);
	printf("\t0x%x\t\tFile address of relocation table\n", dosHeader->e_lfarlc);
	printf("\t0x%x\t\tOverlay number\n", dosHeader->e_ovno);
	printf("\t0x%x\t\tOEM identifier (for e_oeminfo)\n", dosHeader->e_oemid);
	printf("\t0x%x\t\tOEM information; e_oemid specific\n", dosHeader->e_oeminfo);
	printf("\t0x%x\t\tFile address of new exe header\n", dosHeader->e_lfanew);
	printf("-------------------------------------------------------------------------\n");
}

void printNTHeader(PIMAGE_NT_HEADERS nTheader) {
	printf("-- PE NT HEADERS --------------------------------------------------------\n");
	printf("\t%x\t\tSignature\n", nTheader->Signature);
	printf("-------------------------------------------------------------------------\n");
}

void printFileHeader(PIMAGE_FILE_HEADER fileHeader) {
	printf("-- PE FILE HEADER -------------------------------------------------------\n");
	printf("\t0x%x\t\tMachine\n", fileHeader->Machine);
	printf("\t0x%x\t\tNumber of Sections\n", fileHeader->NumberOfSections);
	printf("\t0x%x\tTime Stamp\n", fileHeader->TimeDateStamp);
	printf("\t0x%x\t\tPointer to Symbol Table\n", fileHeader->PointerToSymbolTable);
	printf("\t0x%x\t\tNumber of Symbols\n", fileHeader->NumberOfSymbols);
	printf("\t0x%x\t\tSize of Optional Header\n", fileHeader->SizeOfOptionalHeader);
	printf("\t0x%x\t\tCharacteristics\n", fileHeader->Characteristics);
	printf("-------------------------------------------------------------------------\n");
}

void printOptionalHeader(PIMAGE_OPTIONAL_HEADER  optionalHeader) {
	printf("-- PE OPTIONAL HEADER ---------------------------------------------------\n");
	printf("\t0x%x\t\tMagic\n", optionalHeader->Magic);
	printf("\t0x%x\t\tMajor Linker Version\n", optionalHeader->MajorLinkerVersion);
	printf("\t0x%x\t\tMinor Linker Version\n", optionalHeader->MinorLinkerVersion);
	printf("\t0x%x\t\tSize Of Code\n", optionalHeader->SizeOfCode);
	printf("\t0x%x\t\tSize Of Initialized Data\n", optionalHeader->SizeOfInitializedData);
	printf("\t0x%x\t\tSize Of UnInitialized Data\n", optionalHeader->SizeOfUninitializedData);
	printf("\t0x%x\t\tAddress Of Entry Point (.text)\n", optionalHeader->AddressOfEntryPoint);
	printf("\t0x%x\t\tBase Of Code\n", optionalHeader->BaseOfCode);
	printf("\t0x%x\t\tImage Base\n", optionalHeader->ImageBase);
	printf("\t0x%x\t\tSection Alignment\n", optionalHeader->SectionAlignment);
	printf("\t0x%x\t\tFile Alignment\n", optionalHeader->FileAlignment);
	printf("\t0x%x\t\tMajor Operating System Version\n", optionalHeader->MajorOperatingSystemVersion);
	printf("\t0x%x\t\tMinor Operating System Version\n", optionalHeader->MinorOperatingSystemVersion);
	printf("\t0x%x\t\tMajor Image Version\n", optionalHeader->MajorImageVersion);
	printf("\t0x%x\t\tMinor Image Version\n", optionalHeader->MinorImageVersion);
	printf("\t0x%x\t\tMajor Subsystem Version\n", optionalHeader->MajorSubsystemVersion);
	printf("\t0x%x\t\tMinor Subsystem Version\n", optionalHeader->MinorSubsystemVersion);
	printf("\t0x%x\t\tWin32 Version Value\n", optionalHeader->Win32VersionValue);
	printf("\t0x%x\t\tSize Of Image\n", optionalHeader->SizeOfImage);
	printf("\t0x%x\t\tSize Of Headers\n", optionalHeader->SizeOfHeaders);
	printf("\t0x%x\t\tCheckSum\n", optionalHeader->CheckSum);
	printf("\t0x%x\t\tSubsystem\n", optionalHeader->Subsystem);
	printf("\t0x%x\t\tDllCharacteristics\n", optionalHeader->DllCharacteristics);
	printf("\t0x%x\t\tSize Of Stack Reserve\n", optionalHeader->SizeOfStackReserve);
	printf("\t0x%x\t\tSize Of Stack Commit\n", optionalHeader->SizeOfStackCommit);
	printf("\t0x%x\t\tSize Of Heap Reserve\n", optionalHeader->SizeOfHeapReserve);
	printf("\t0x%x\t\tSize Of Heap Commit\n", optionalHeader->SizeOfHeapCommit);
	printf("\t0x%x\t\tLoader Flags\n", optionalHeader->LoaderFlags);
	printf("\t0x%x\t\tNumber Of Rva And Sizes\n", optionalHeader->NumberOfRvaAndSizes);
	printf("-------------------------------------------------------------------------\n");

}

void printDirectoryAddress(PIMAGE_DATA_DIRECTORY dataDirectory) {
	printf("-- PE DATA DIRECTORIES --------------------------------------------------\n");
	printf("\tExport Directory Address: 0x%x; Size: 0x%x\n", dataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, dataDirectory[0].Size);
	printf("\tImport Directory Address: 0x%x; Size: 0x%x\n", dataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, dataDirectory[1].Size);
	printf("-------------------------------------------------------------------------\n");
}

void printSection(PIMAGE_SECTION_HEADER sectionHeader) {

	printf("\t%s\n", sectionHeader->Name);
	printf("\t\t0x%x\t\tVirtual Size\n", sectionHeader->Misc.VirtualSize);
	printf("\t\t0x%x\t\tVirtual Address\n", sectionHeader->VirtualAddress);
	printf("\t\t0x%x\t\tSize Of Raw Data\n", sectionHeader->SizeOfRawData);
	printf("\t\t0x%x\t\tPointer To Raw Data\n", sectionHeader->PointerToRawData);
	printf("\t\t0x%x\t\tPointer To Relocations\n", sectionHeader->PointerToRelocations);
	printf("\t\t0x%x\t\tPointer To Line Numbers\n", sectionHeader->PointerToLinenumbers);
	printf("\t\t0x%x\t\tNumber Of Relocations\n", sectionHeader->NumberOfRelocations);
	printf("\t\t0x%x\t\tNumber Of Line Numbers\n", sectionHeader->NumberOfLinenumbers);
	printf("\t\t0x%x\tCharacteristics\n", sectionHeader->Characteristics);
}

void printImport() {
}

int routing(PIMAGE_DOS_HEADER dosHeader, PIMAGE_NT_HEADERS ntHeader, PIMAGE_FILE_HEADER fileHeader, PIMAGE_OPTIONAL_HEADER optionalHeader, PIMAGE_DATA_DIRECTORY directory, PBYTE buffer) {

	printMenuHeader();
	int val = printOptions();
	printf("\n");

	PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)(buffer + dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));
	DWORD sectionSize = (DWORD)sizeof(IMAGE_SECTION_HEADER);

	DWORD importDirectoryRVA = directory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	PIMAGE_SECTION_HEADER importSection = NULL;

	//finding import section
	for (int i = 0; i < fileHeader->NumberOfSections; i++)
	{
		int indexOffset = i * sectionSize;
		sectionHeader = (PIMAGE_SECTION_HEADER)(buffer + dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + indexOffset);
		if (importDirectoryRVA >= sectionHeader->VirtualAddress && importDirectoryRVA < sectionHeader->VirtualAddress + sectionHeader->Misc.VirtualSize) {
			importSection = sectionHeader;
			break;
		}
	}

	switch (val)
	{
	case DOS_HEADER:
		printDosHeader(dosHeader);
		break;
	case NT_HEADER:
		printNTHeader(ntHeader);
		break;
	case FILE_HEADER:
		printFileHeader(fileHeader);
		break;
	case OPTIONAL_HEADER:
		printOptionalHeader(optionalHeader);
		break;
	case DIRECTORY_ADDRESS:
		printDirectoryAddress(directory);
		break;
	case SECTIONS:
	{
		printf("-- PE SECTION HEADERS ---------------------------------------------------\n");

		for (int i = 0; i < fileHeader->NumberOfSections; i++)
		{
			int indexOffset = i * sectionSize;
			sectionHeader = (PIMAGE_SECTION_HEADER)(buffer + dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + indexOffset);
			printSection(sectionHeader);
		}

		printf("-------------------------------------------------------------------------\n");

		break;
	}
	case IMPORTS:
	{

		printf("-- PE DLL IMPORTS ---------------------------------------------------\n");

		if (importSection != NULL) {

			PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(buffer + importSection->PointerToRawData + (directory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress - importSection->VirtualAddress));

			for (; importDescriptor->Name != 0; importDescriptor++) {

				char* dllName = (char*)(buffer + importSection->PointerToRawData + (importDescriptor->Name - importSection->VirtualAddress));
				printf("\t%s\n", dllName);

				DWORD thunk = NULL;

				if (importDescriptor->OriginalFirstThunk == 0) {
					thunk = importDescriptor->FirstThunk;
				}
				else {
					thunk = importDescriptor->OriginalFirstThunk;
				}

				PIMAGE_THUNK_DATA thunkData = (PIMAGE_THUNK_DATA)(buffer + importSection->PointerToRawData + (thunk - importSection->VirtualAddress));

				for (; thunkData->u1.AddressOfData != 0; thunkData++) {

					//a cheap and probably non-reliable way of checking if the function is imported via its ordinal number ¯\_(ツ)_/¯
					if (IMAGE_SNAP_BY_ORDINAL(thunkData->u1.AddressOfData)) {
						//show lower bits of the value to get the ordinal ¯\_(ツ)_/¯
						printf("\t\t\Ordinal: 0x%x\n", (WORD)thunkData->u1.AddressOfData);
					}
					else {
						printf("\t\t%s\n", (buffer + importSection->PointerToRawData + (thunkData->u1.AddressOfData - importSection->VirtualAddress + 2)));
					}
				}
			}

			printf("-------------------------------------------------------------------------\n");
		}

	}
	break;
	case EXIT:
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), attributes);
		exit(0);
	default:
		break;
	}

	printf("Press Double ENTER to return to menu\n");
	_getch();
	flushStdin();
	system("cls");

	return routing(dosHeader, ntHeader, fileHeader, optionalHeader, directory, buffer);
}

int init(int argc, char* argv[]) {

	memcpy_s(&filename, MAX_FILEPATH_LENGTH, argv[1], MAX_FILEPATH_LENGTH);

	file = CreateFileA(filename, GENERIC_ALL, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE) {
		printf("Could not read file\n");
		return -1;
	}

	fileSize = GetFileSize(file, NULL);
	PBYTE buffer = PBYTE(LocalAlloc(LPTR, fileSize));

	BOOL success = ReadFile(file, buffer, fileSize, &bytesRead, NULL);

	if (success) {

		PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)buffer;

		if (dosHeader != NULL && dosHeader->e_magic == IMAGE_DOS_SIGNATURE) {

			PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)dosHeader + dosHeader->e_lfanew);
			PIMAGE_FILE_HEADER fileHeader = (PIMAGE_FILE_HEADER)&ntHeader->FileHeader;

			if (fileHeader->Machine == IMAGE_FILE_MACHINE_I386) {
				is64bit = false;
			}
			else {
				is64bit = true;
			}

			PIMAGE_OPTIONAL_HEADER  optionalHeader = (PIMAGE_OPTIONAL_HEADER)&ntHeader->OptionalHeader;
			PIMAGE_DATA_DIRECTORY directory = (PIMAGE_DATA_DIRECTORY)&ntHeader->OptionalHeader.DataDirectory;

			PIMAGE_SECTION_HEADER importSection = NULL;

			routing(dosHeader, ntHeader, fileHeader, optionalHeader, directory, buffer);
			return 0;

		}
	}
}

int main(int argc, char* argv[])
{
	if (argc <= 1) {
		printf("PEReader 0.2 | Args Missing!\nPER.exe <EXE>\nRudenetworks.com\n");
		return -1;
	}

	CONSOLE_SCREEN_BUFFER_INFO Info;
	hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	GetConsoleScreenBufferInfo(hConsole, &Info);
	attributes = Info.wAttributes;

	signal(SIGINT, sigfun);

	while (1) {
		int e = init(argc, argv);
		break;
	}


}
