#pragma once
#include <cstdio>
#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>

#define NT_SUCCESS(x) ((x) >= 0)

typedef NTSTATUS(NTAPI* _NtWriteVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, LPCVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten);
_NtWriteVirtualMemory NtWriteVirtualMemory = (_NtWriteVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");

typedef NTSTATUS(NTAPI* _NtReadVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesRead);
_NtReadVirtualMemory NtReadVirtualMemory = (_NtReadVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtReadVirtualMemory");

namespace VeduMemory
{
	namespace Externals
	{
		HANDLE processHandle;
		DWORD processID;
	}

	namespace KernelMode
	{
		template <class dataType>
		dataType Read(DWORD addressToRead)
		{
			dataType rpmBuffer;
			NtReadVirtualMemory(Externals::processHandle, (PVOID)addressToRead, &rpmBuffer, sizeof(dataType), 0);
			return rpmBuffer;
		}
		
		template <class dataType>
		void Write(DWORD addressToWrite, dataType ValueToWrite)
		{
			DWORD oldProtect = 0;
			NTSTATUS Status = 0;
			VirtualProtectEx(Externals::processHandle, (PVOID)addressToWrite, sizeof(dataType), PAGE_EXECUTE_READWRITE, &oldProtect);

			if (!NT_SUCCESS(Status = NtWriteVirtualMemory(Externals::processHandle, (PVOID)addressToWrite, &ValueToWrite, sizeof(dataType), NULL)))
				std::cout << Status << std::endl;

			VirtualProtectEx(Externals::processHandle, (PVOID)addressToWrite, sizeof(dataType), oldProtect, NULL);
		}

		template <class dataType>
		void Write(DWORD addressToWrite, dataType* ValueToWrite)
		{
			DWORD oldProtect = 0;
			NTSTATUS Status = 0;
			VirtualProtectEx(Externals::processHandle, (PVOID)addressToWrite, sizeof(dataType), PAGE_EXECUTE_READWRITE, &oldProtect);

			if (!NT_SUCCESS(Status = NtWriteVirtualMemory(Externals::processHandle, (PVOID)addressToWrite, ValueToWrite, sizeof(dataType), NULL)))
				std::cout << Status << std::endl;

			VirtualProtectEx(Externals::processHandle, (PVOID)addressToWrite, sizeof(dataType), oldProtect, NULL);
		}
	}

	namespace UserMode
	{
		template <typename T> 
		T Read(SIZE_T targetAddress) {
			T Buffer;
			ReadProcessMemory(Externals::processHandle, (LPCVOID)targetAddress, &Buffer, sizeof(T), NULL);
			return Buffer;
		}

		template <typename T> 
		void Write(SIZE_T targetAddress, T Buffer) {
			WriteProcessMemory(Externals::processHandle, (LPVOID)targetAddress, &Buffer, sizeof(Buffer), NULL);
		}

		uintptr_t GetModuleAddress(const char* moduleName)
		{
			HANDLE snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, Externals::processID);
			if (snapshotHandle != INVALID_HANDLE_VALUE)
			{
				MODULEENTRY32 modEntry;
				modEntry.dwSize = sizeof(modEntry);
				if (Module32First(snapshotHandle, &modEntry))
				{
					do {
						if (!strcmp(modEntry.szModule, moduleName))
						{
							CloseHandle(snapshotHandle);
							return (uintptr_t)modEntry.modBaseAddr;
						}
					} while (Module32Next(snapshotHandle, &modEntry));
				}
			}
			return FALSE;
		}
	}
}
