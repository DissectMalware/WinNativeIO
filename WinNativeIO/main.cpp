#include "stdafx.h"

#include <iostream>
#include <Windows.h>
#include <string> 
#include "NativeIO.h"

using namespace std;

int main()
{
	_NtCreateFile NtCreateFile = (_NtCreateFile)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtCreateFile");
	_NtReadFile NtReadFile = (_NtReadFile)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtReadFile");
	_NtWriteFile NtWriteFile = (_NtWriteFile)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtWriteFile");
	_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlInitUnicodeString");

	HANDLE hFile;
	OBJECT_ATTRIBUTES objAttribs = { 0 };

	string operation;
	string fullPath;

	cout << "Choose an operation: read/write/delete" << endl;
	cin >> operation;
	cin.ignore();

	cout << "Enter a full path:" << endl;
	getline(cin, fullPath);

	wchar_t buffer[1024];
	swprintf(buffer, 1024, L"\\??\\%s", wstring(fullPath.begin(), fullPath.end()).c_str());
	// Initializing unicode string
	UNICODE_STRING unicodeString;
	RtlInitUnicodeString(&unicodeString, buffer);

	// Calling InitializeObjectAttributes to initialize OBJECT_ATTRIBUTES data structure.;
	InitializeObjectAttributes(&objAttribs, &unicodeString, OBJ_CASE_INSENSITIVE, NULL, NULL);

	// Initializing LARGE_INTEGER for allocation size
	const int allocSize = 2048;
	LARGE_INTEGER largeInteger;
	largeInteger.QuadPart = allocSize;
	  

	IO_STATUS_BLOCK ioStatusBlock = { 0 };
	if (strcmp(operation.c_str(), "read") == 0)
	{
		cout << "[Calling NtCreateFile...]" << endl;

		ioStatusBlock = { 0 };
		NTSTATUS op = NtCreateFile(&hFile, FILE_READ_DATA | SYNCHRONIZE, &objAttribs, &ioStatusBlock, &largeInteger,
			FILE_ATTRIBUTE_NORMAL, FILE_READ_ACCESS, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_ALERT, NULL, NULL);

		if (op == STATUS_SUCCESS)
		{
			PVOID FileReadBuffer;
			const int BUFFER_SIZE = 100;
			FileReadBuffer = new CHAR[BUFFER_SIZE];
			LARGE_INTEGER liByteOffset = { 0 };
			cout << "[Calling NtReadFile...]" << endl;
			cout << "[File is read]" << endl;

			while (true)
			{
				op = NtReadFile(hFile, NULL, NULL, NULL, &ioStatusBlock, FileReadBuffer, BUFFER_SIZE-1, &liByteOffset, NULL);
				if (op == STATUS_SUCCESS)
				{
					((char *)FileReadBuffer)[ioStatusBlock.Information] = '\0';
					
					cout << (char*)FileReadBuffer;
					liByteOffset.LowPart += ioStatusBlock.Information;
				}
				else if (op == STATUS_EOF)
				{
					cout << endl;
					break;
				}
				else
				{
					cout << "ERROR " << stat << endl;
					break;
				}
			}
			cout << "[Calling CloseHandle...]" << endl;
			delete[] FileReadBuffer;
			CloseHandle(hFile);
		}
	}
	else if (strcmp(operation.c_str(), "write") == 0)
	{
		cout << "[Calling NtCreateFile...]" << endl;

		NTSTATUS op = NtCreateFile(&hFile, FILE_WRITE_DATA, &objAttribs, &ioStatusBlock, &largeInteger,
			FILE_ATTRIBUTE_NORMAL, FILE_WRITE_ACCESS, FILE_OPEN | FILE_CREATE, FILE_NON_DIRECTORY_FILE, NULL, NULL);

		if (op == STATUS_SUCCESS)
		{
			cout << "[File is created]" << endl;
			PVOID FileReadBuffer;
			cout << "Enter a line to be written in the file" << endl;
			string *content = new string();
			getline(cin, *content);

			LARGE_INTEGER liByteOffset = { 0 };
			cout << "[Calling NtWriteFile...]" << endl;
			NTSTATUS stat = NtWriteFile(hFile, NULL, NULL, NULL, &ioStatusBlock, (PVOID) (content->c_str()), content->length(), &liByteOffset, NULL);
			if (stat == STATUS_SUCCESS || stat == 0x00000103)
			{
				cout << "[File is written]" << endl;
			}
			else
			{
				
				cout << "ERROR " << stat << endl;
			}
			cout << "[Calling CloseHandle...]" << endl;
			delete content;
			CloseHandle(hFile);
		}

	}
	else if (strcmp(operation.c_str(), "delete") == 0)
	{
		cout << "[Calling NtCreateFile...]" << endl;

		ioStatusBlock = { 0 };
		NTSTATUS op = NtCreateFile(&hFile, DELETE, &objAttribs, &ioStatusBlock, &largeInteger,
			FILE_ATTRIBUTE_NORMAL,  FILE_SHARE_DELETE, FILE_OPEN, 0x00001000, NULL, NULL);
		if (op == STATUS_SUCCESS)
		{
			cout << "[File is deleted]" << endl;
			CloseHandle(hFile);
		}
	}
	else
	{
		cout << "[ERROR Invalid operation]" << endl;
	}

	cin.get();
}
