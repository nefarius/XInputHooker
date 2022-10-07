//
// WinAPI
// 
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <SetupAPI.h>
#include <Shlwapi.h>
#include <initguid.h>
#include <winioctl.h>
#include "XUSB.h"

//
// STL
// 
#include <string>
#include <codecvt>
#include <locale>
#include <map>
#include <iostream>
#include <fstream>

//
// JSON
// 
#include <json/json.h>

//
// Hooking
// 
#include <detours/detours.h>

//
// Logging
// 
#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/fmt/bin_to_hex.h>

using convert_t = std::codecvt_utf8<wchar_t>;
std::wstring_convert<convert_t, wchar_t> strconverter;
std::once_flag g_init;
std::string g_dllDir;


static decltype(SetupDiEnumDeviceInterfaces) *real_SetupDiEnumDeviceInterfaces = SetupDiEnumDeviceInterfaces;
static decltype(DeviceIoControl) *real_DeviceIoControl = DeviceIoControl;
static decltype(CreateFileA) *real_CreateFileA = CreateFileA;
static decltype(CreateFileW) *real_CreateFileW = CreateFileW;
static decltype(WriteFile)* real_WriteFile = WriteFile;
static decltype(CloseHandle)* real_CloseHandle = CloseHandle;
static decltype(GetOverlappedResult)* real_GetOverlappedResult = GetOverlappedResult;

static std::map<HANDLE, std::string> g_handleToPath;
static std::map<DWORD, std::string> g_ioctlMap;


//
// Hooks SetupDiEnumDeviceInterfaces() API
// 
BOOL WINAPI DetourSetupDiEnumDeviceInterfaces(
	HDEVINFO DeviceInfoSet,
	PSP_DEVINFO_DATA DeviceInfoData,
	const GUID* InterfaceClassGuid,
	DWORD MemberIndex,
	PSP_DEVICE_INTERFACE_DATA DeviceInterfaceData
)
{
	std::shared_ptr<spdlog::logger> _logger = spdlog::get("XInputHooker")->clone("SetupDiEnumDeviceInterfaces");

	auto retval = real_SetupDiEnumDeviceInterfaces(DeviceInfoSet, DeviceInfoData, InterfaceClassGuid, MemberIndex,
	                                               DeviceInterfaceData);

	_logger->info("InterfaceClassGuid = {{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}, "
	              "success = {}, error = 0x{:08X}",
	              InterfaceClassGuid->Data1, InterfaceClassGuid->Data2, InterfaceClassGuid->Data3,
	              InterfaceClassGuid->Data4[0], InterfaceClassGuid->Data4[1], InterfaceClassGuid->Data4[2],
	              InterfaceClassGuid->Data4[3],
	              InterfaceClassGuid->Data4[4], InterfaceClassGuid->Data4[5], InterfaceClassGuid->Data4[6],
	              InterfaceClassGuid->Data4[7],
	              retval ? "true" : "false",
				  retval ? ERROR_SUCCESS : GetLastError());

	return retval;
}

//
// Hooks CreateFileA() API
// 
HANDLE WINAPI DetourCreateFileA(
	LPCSTR lpFileName,
	DWORD dwDesiredAccess,
	DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile
)
{
	std::shared_ptr<spdlog::logger> _logger = spdlog::get("XInputHooker")->clone("CreateFileA");
	std::string path(lpFileName);

	const bool isOfInterest = (path.rfind("\\\\", 0) == 0);

	const auto handle = real_CreateFileA(
		lpFileName,
		dwDesiredAccess,
		dwShareMode,
		lpSecurityAttributes,
		dwCreationDisposition,
		dwFlagsAndAttributes,
		hTemplateFile
	);

	if (isOfInterest)
	{
		if (handle != INVALID_HANDLE_VALUE)
		{
			g_handleToPath[handle] = path;
			_logger->info("handle = {}, lpFileName = {}", handle, path);
		}
		else
		{
			_logger->info("lpFileName = {}, lastError = {}", path, GetLastError());
		}
	}

	return handle;
}

//
// Hooks CreateFileW() API
// 
HANDLE WINAPI DetourCreateFileW(
	LPCWSTR lpFileName,
	DWORD dwDesiredAccess,
	DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile
)
{
	std::shared_ptr<spdlog::logger> _logger = spdlog::get("XInputHooker")->clone("CreateFileW");
	std::string path(strconverter.to_bytes(lpFileName));

	const bool isOfInterest = (path.rfind("\\\\", 0) == 0);

	const auto handle = real_CreateFileW(
		lpFileName,
		dwDesiredAccess,
		dwShareMode,
		lpSecurityAttributes,
		dwCreationDisposition,
		dwFlagsAndAttributes,
		hTemplateFile
	);

	if (isOfInterest)
	{
		if (handle != INVALID_HANDLE_VALUE)
		{
			g_handleToPath[handle] = path;
			_logger->info("handle = {}, lpFileName = {}", handle, path);
		}
		else
		{
			_logger->info("lpFileName = {}, lastError = {}", path, GetLastError());
		}
	}

	return handle;
}

//
// Hooks WriteFile() API
// 
BOOL WINAPI DetourWriteFile(
	HANDLE       hFile,
	LPCVOID      lpBuffer,
	DWORD        nNumberOfBytesToWrite,
	LPDWORD      lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped
)
{
	std::shared_ptr<spdlog::logger> _logger = spdlog::get("XInputHooker")->clone("WriteFile");

	const PUCHAR charInBuf = PUCHAR(lpBuffer);
	DWORD tmpBytesWritten;
	
	const auto ret =  real_WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, &tmpBytesWritten, lpOverlapped);
	const auto error = GetLastError();

	if (lpNumberOfBytesWritten)
		*lpNumberOfBytesWritten = tmpBytesWritten;

	std::string path = "Unknown";
	if (g_handleToPath.count(hFile))
	{
		path = g_handleToPath[hFile];
	}
#ifndef XINPUTHOOKER_LOG_UNKNOWN_HANDLES
	else
	{
		// Ignore unknown handles
		return ret;
	}
#endif

	const auto bufSize = std::min(nNumberOfBytesToWrite, tmpBytesWritten);
	const std::vector<char> inBuffer(charInBuf, charInBuf + bufSize);
	
	// Prevent the logger from causing a crash via exception when it double-detours WriteFile
	try
	{
		_logger->info("success = {}, lastError = 0x{:08X}, path = {} ({:04d}) -> {:Xpn}",
			ret ? "true" : "false",
			ret ? ERROR_SUCCESS : error,
			path,
			bufSize,
			spdlog::to_hex(inBuffer)
		);
	}
	catch (...)
	{ }

	return ret;
}

BOOL DetourCloseHandle(
	HANDLE hObject
)
{
	std::shared_ptr<spdlog::logger> _logger = spdlog::get("XInputHooker")->clone("CloseHandle");

	const auto ret = real_CloseHandle(hObject);

	std::string path = "Unknown";
	if (g_handleToPath.count(hObject))
	{
		path = g_handleToPath[hObject];
		g_handleToPath.erase(hObject);
	}
#ifndef XINPUTHOOKER_LOG_UNKNOWN_HANDLES
	else
	{
		// Ignore unknown handles
		return ret;
	}
#endif

	_logger->info("handle = {}, path = {}", hObject, path);

	return ret;
}

BOOL WINAPI DetourGetOverlappedResult(
	HANDLE       hFile,
	LPOVERLAPPED lpOverlapped,
	LPDWORD      lpNumberOfBytesTransferred,
	BOOL         bWait
)
{
	std::shared_ptr<spdlog::logger> _logger = spdlog::get("XInputHooker")->clone("GetOverlappedResult");
	DWORD tmpBytesTransferred;

	const auto ret = real_GetOverlappedResult(hFile, lpOverlapped, &tmpBytesTransferred, bWait);
	const auto error = GetLastError();

	if (lpNumberOfBytesTransferred)
		*lpNumberOfBytesTransferred = tmpBytesTransferred;
	
	std::string path = "Unknown";
	if (g_handleToPath.count(hFile))
	{
		path = g_handleToPath[hFile];
	}
#ifndef XINPUTHOOKER_LOG_UNKNOWN_HANDLES
	else
	{
		// Ignore unknown handles
		return ret;
	}
#endif

	_logger->info("success = {}, lastError = 0x{:08X}, bytesTransferred = {}, path = {}",
		ret ? "true" : "false",
		ret ? ERROR_SUCCESS : error,
		tmpBytesTransferred,
		path
	);
	
	return ret;
}

//
// Hooks DeviceIoControl() API
// 
BOOL WINAPI DetourDeviceIoControl(
	HANDLE hDevice,
	DWORD dwIoControlCode,
	LPVOID lpInBuffer,
	DWORD nInBufferSize,
	LPVOID lpOutBuffer,
	DWORD nOutBufferSize,
	LPDWORD lpBytesReturned,
	LPOVERLAPPED lpOverlapped
)
{
	std::shared_ptr<spdlog::logger> _logger = spdlog::get("XInputHooker")->clone("DeviceIoControl");

	const PUCHAR charInBuf = static_cast<PUCHAR>(lpInBuffer);
	const std::vector<char> inBuffer(charInBuf, charInBuf + nInBufferSize);

	DWORD tmpBytesReturned;

	const auto retval = real_DeviceIoControl(
		hDevice,
		dwIoControlCode,
		lpInBuffer,
		nInBufferSize,
		lpOutBuffer,
		nOutBufferSize,
		&tmpBytesReturned, // might be null, use our own variable
		lpOverlapped
	);

	if (lpBytesReturned)
		*lpBytesReturned = tmpBytesReturned;

	std::string path = "Unknown";
	if (g_handleToPath.count(hDevice))
	{
		path = g_handleToPath[hDevice];
	}
#ifndef XINPUTHOOKER_LOG_UNKNOWN_HANDLES
	else
	{
		// Ignore unknown handles
		return retval;
	}
#endif

	if (g_ioctlMap.count(dwIoControlCode))
	{
		_logger->info("[I] [{}] path = {} ({:04d}) -> {:Xpn}",
		              g_ioctlMap[dwIoControlCode],
		              path,
		              nInBufferSize,
		              spdlog::to_hex(inBuffer)
		);
	}

	if (lpOutBuffer && nOutBufferSize > 0)
	{
		const PUCHAR charOutBuf = static_cast<PUCHAR>(lpOutBuffer);
		const auto bufSize = std::min(nOutBufferSize, tmpBytesReturned);
		const std::vector<char> outBuffer(charOutBuf, charOutBuf + bufSize);

		if (g_ioctlMap.count(dwIoControlCode))
		{
			_logger->info("[O] [{}] path = {} ({:04d}) -> {:Xpn}",
			              g_ioctlMap[dwIoControlCode],
			              path,
			              bufSize,
			              spdlog::to_hex(outBuffer)
			);
		}
	}

	return retval;
}

EXTERN_C IMAGE_DOS_HEADER __ImageBase;

BOOL WINAPI DllMain(HINSTANCE dll_handle, DWORD reason, LPVOID reserved)
{
	if (DetourIsHelperProcess())
	{
		return TRUE;
	}

	switch (reason)
	{
	case DLL_PROCESS_ATTACH:
		{
			CHAR dllPath[MAX_PATH];

			GetModuleFileNameA((HINSTANCE)&__ImageBase, dllPath, MAX_PATH);
			PathRemoveFileSpecA(dllPath);
			g_dllDir = std::string(dllPath);

			auto logger = spdlog::basic_logger_mt(
				"XInputHooker",
				g_dllDir + "\\XInputHooker.log"
			);

#if _DEBUG
			spdlog::set_level(spdlog::level::debug);
			logger->flush_on(spdlog::level::debug);
#else
			logger->flush_on(spdlog::level::info);
#endif

			set_default_logger(logger);

			//
			// Load known IOCTL code definitions
			// 
			Json::Value root;
			std::ifstream ifs(g_dllDir + "\\ioctls.json");
			ifs >> root;

			for (auto& i : root)
			{
				g_ioctlMap[std::stoul(i["HexValue"].asString(), nullptr, 16)] = i["Ioctl"].asString();
			}
		}

		DisableThreadLibraryCalls(dll_handle);
		DetourRestoreAfterWith();

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach((PVOID*)&real_SetupDiEnumDeviceInterfaces, DetourSetupDiEnumDeviceInterfaces);
		DetourAttach((PVOID*)&real_DeviceIoControl, DetourDeviceIoControl);
		DetourAttach((PVOID*)&real_CreateFileA, DetourCreateFileA);
		DetourAttach((PVOID*)&real_CreateFileW, DetourCreateFileW);
		DetourAttach((PVOID*)&real_WriteFile, DetourWriteFile);
		DetourAttach((PVOID*)&real_CloseHandle, DetourCloseHandle);
		DetourAttach((PVOID*)&real_GetOverlappedResult, DetourGetOverlappedResult);
		DetourTransactionCommit();

		break;

	case DLL_PROCESS_DETACH:
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourDetach((PVOID*)&real_SetupDiEnumDeviceInterfaces, DetourSetupDiEnumDeviceInterfaces);
		DetourDetach((PVOID*)&real_DeviceIoControl, DetourDeviceIoControl);
		DetourDetach((PVOID*)&real_CreateFileA, DetourCreateFileA);
		DetourDetach((PVOID*)&real_CreateFileW, DetourCreateFileW);
		DetourDetach((PVOID*)&real_WriteFile, DetourWriteFile);
		DetourDetach((PVOID*)&real_CloseHandle, DetourCloseHandle);
		DetourDetach((PVOID*)&real_GetOverlappedResult, DetourGetOverlappedResult);
		DetourTransactionCommit();
		break;
	}
	return TRUE;
}
