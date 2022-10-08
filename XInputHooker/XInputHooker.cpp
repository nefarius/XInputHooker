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

struct ReadFileExDetourParams
{
	HANDLE hFile;
	LPVOID lpBuffer;
	DWORD  nNumberOfBytesToRead;
	LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine;
};

static decltype(SetupDiEnumDeviceInterfaces) *real_SetupDiEnumDeviceInterfaces = SetupDiEnumDeviceInterfaces;
static decltype(DeviceIoControl) *real_DeviceIoControl = DeviceIoControl;
static decltype(CreateFileA) *real_CreateFileA = CreateFileA;
static decltype(CreateFileW) *real_CreateFileW = CreateFileW;
static decltype(ReadFile)* real_ReadFile = ReadFile;
static decltype(ReadFileEx)* real_ReadFileEx = ReadFileEx;
static decltype(WriteFile)* real_WriteFile = WriteFile;
static decltype(CloseHandle)* real_CloseHandle = CloseHandle;
static decltype(GetOverlappedResult)* real_GetOverlappedResult = GetOverlappedResult;

static std::map<HANDLE, std::string> g_handleToPath;
static std::map<LPOVERLAPPED, ReadFileExDetourParams> g_overlappedToRoutine;
static std::map<DWORD, std::string> g_ioctlMap;
static std::map<DWORD, bool> g_newIoctls;


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
// Hooks ReadFile() API
// 
BOOL WINAPI DetourReadFile(
	HANDLE       hFile,
	LPVOID       lpBuffer,
	DWORD        nNumberOfBytesToRead,
	LPDWORD      lpNumberOfBytesRead,
	LPOVERLAPPED lpOverlapped
)
{
	std::shared_ptr<spdlog::logger> _logger = spdlog::get("XInputHooker")->clone("ReadFile");

	const PUCHAR charInBuf = PUCHAR(lpBuffer);
	DWORD tmpBytesRead;

	const auto ret =  real_ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, &tmpBytesRead, lpOverlapped);
	const auto error = GetLastError();

	if (lpNumberOfBytesRead)
		*lpNumberOfBytesRead = tmpBytesRead;

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

	const auto bufSize = std::min(nNumberOfBytesToRead, tmpBytesRead);
	const std::vector<char> outBuffer(charInBuf, charInBuf + bufSize);

	_logger->info("success = {}, lastError = 0x{:08X}, path = {} bytesToRead: {:04d}, bytesRead: {:04d} -> {:Xpn}",
		ret ? "true" : "false",
		ret ? ERROR_SUCCESS : error,
		path,
		nNumberOfBytesToRead,
		tmpBytesRead,
		spdlog::to_hex(outBuffer)
	);

	return ret;
}

void ReadFileExCallback(
	DWORD dwErrorCode,
	DWORD dwNumberOfBytesTransfered,
	LPOVERLAPPED lpOverlapped
)
{
	std::shared_ptr<spdlog::logger> _logger = spdlog::get("XInputHooker")->clone("ReadFileExCallback");

	const auto completionParams = g_overlappedToRoutine[lpOverlapped];
	const auto hFile = completionParams.hFile;
	const auto buffer = completionParams.lpBuffer;
	const auto bufferSize = completionParams.nNumberOfBytesToRead;
	const auto completionRoutine = completionParams.lpCompletionRoutine;
	g_overlappedToRoutine.erase(lpOverlapped);

	std::string path = "Unknown";
	if (g_handleToPath.count(hFile))
	{
		path = g_handleToPath[hFile];
	}
#ifndef XINPUTHOOKER_LOG_UNKNOWN_HANDLES
	else
	{
		// Ignore unknown handles
		if (completionRoutine)
			completionRoutine(dwErrorCode, dwNumberOfBytesTransfered, lpOverlapped);
		return;
	}
#endif

	const PUCHAR charInBuf = PUCHAR(buffer);
	const auto bufSize = std::min(bufferSize, dwNumberOfBytesTransfered);
	const std::vector<char> outBuffer(charInBuf, charInBuf + bufSize);

	_logger->info("result = 0x{:08X}, path = {} ({:04d}) -> {:Xpn}",
		dwErrorCode,
		path,
		bufSize,
		spdlog::to_hex(outBuffer)
	);

	completionRoutine(dwErrorCode, dwNumberOfBytesTransfered, lpOverlapped);
}

//
// Hooks ReadFileEx() API
// 
BOOL WINAPI DetourReadFileEx(
	HANDLE       hFile,
	LPVOID       lpBuffer,
	DWORD        nNumberOfBytesToRead,
	LPOVERLAPPED lpOverlapped,
	LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
)
{
	std::shared_ptr<spdlog::logger> _logger = spdlog::get("XInputHooker")->clone("ReadFileEx");

	std::string path = "Unknown";
	if (g_handleToPath.count(hFile))
	{
		path = g_handleToPath[hFile];
	}
#ifndef XINPUTHOOKER_LOG_UNKNOWN_HANDLES
	else
	{
		// Ignore unknown handles
		return real_ReadFileEx(hFile, lpBuffer, nNumberOfBytesToRead, lpOverlapped, lpCompletionRoutine);
	}
#endif

	if (g_overlappedToRoutine.count(lpOverlapped))
	{
		_logger->warn("Same OVERLAPPED used multiple times, passing through directly to function");
		return real_ReadFileEx(hFile, lpBuffer, nNumberOfBytesToRead, lpOverlapped, lpCompletionRoutine);
	}
	g_overlappedToRoutine[lpOverlapped] = { hFile, lpBuffer, nNumberOfBytesToRead, lpCompletionRoutine };

	const auto ret = real_ReadFileEx(hFile, lpBuffer, nNumberOfBytesToRead, lpOverlapped, ReadFileExCallback);
	const auto error = GetLastError();

	_logger->info("success = {}, lastError = 0x{:08X}, path = {}, bufferSize = {}",
		ret ? "true" : "false",
		error,
		path,
		nNumberOfBytesToRead
	);

	return ret;
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

	const std::vector<char> inBuffer(charInBuf, charInBuf + nNumberOfBytesToWrite);
	
	// Prevent the logger from causing a crash via exception when it double-detours WriteFile
	try
	{
		_logger->info("success = {}, lastError = 0x{:08X}, path = {}, bytesToWrite: {:04d}, bytesWritten: {:04d} -> {:Xpn}",
			ret ? "true" : "false",
			ret ? ERROR_SUCCESS : error,
			path,
			nNumberOfBytesToWrite,
			tmpBytesWritten,
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
#ifdef XINPUTHOOKER_LOG_UNKNOWN_IOCTLS
	else
	{
		// Add control code to list of unknown codes
		g_newIoctls[dwIoControlCode] = true;
		_logger->info("[I] [0x{:08X}] path = {} ({:04d}) -> {:Xpn}",
		              dwIoControlCode,
		              path,
		              nInBufferSize,
		              spdlog::to_hex(inBuffer)
		);
	}
#endif

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
#ifdef XINPUTHOOKER_LOG_UNKNOWN_IOCTLS
		else
		{
			_logger->info("[O] [0x{:08X}] path = {} ({:04d}) -> {:Xpn}",
			              dwIoControlCode,
			              path,
			              bufSize,
			              spdlog::to_hex(outBuffer)
			);
		}
#endif
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
		DetourAttach((PVOID*)&real_ReadFile, DetourReadFile);
		DetourAttach((PVOID*)&real_ReadFileEx, DetourReadFileEx);
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
		DetourDetach((PVOID*)&real_ReadFile, DetourReadFile);
		DetourDetach((PVOID*)&real_ReadFileEx, DetourReadFileEx);
		DetourDetach((PVOID*)&real_WriteFile, DetourWriteFile);
		DetourDetach((PVOID*)&real_CloseHandle, DetourCloseHandle);
		DetourDetach((PVOID*)&real_GetOverlappedResult, DetourGetOverlappedResult);
		DetourTransactionCommit();

#ifdef XINPUTHOOKER_LOG_UNKNOWN_IOCTLS
		if (g_newIoctls.size() > 0)
		{
			std::shared_ptr<spdlog::logger> _logger = spdlog::get("XInputHooker")->clone("NewIoctls");
			_logger->info("New IOCTLs:");
			for (auto ioctl : g_newIoctls)
			{
				DWORD code = ioctl.first;
				DWORD deviceType = DEVICE_TYPE_FROM_CTL_CODE(code);
				DWORD function = (code & 0x3FFC) >> 2;
				DWORD method = METHOD_FROM_CTL_CODE(code);
				DWORD access = (code & 0xC000) >> 14;

				std::string methodName =
					method == METHOD_BUFFERED ? "METHOD_BUFFERED" :
					method == METHOD_IN_DIRECT ? "METHOD_IN_DIRECT" :
					method == METHOD_OUT_DIRECT ? "METHOD_OUT_DIRECT" :
					method == METHOD_NEITHER ? "METHOD_NEITHER" :
					"INVALID_METHOD";

				std::string accessName =
					method == FILE_ANY_ACCESS ? "FILE_ANY_ACCESS" :
					method == FILE_READ_ACCESS ? "FILE_READ_ACCESS" :
					method == FILE_WRITE_ACCESS ? "FILE_WRITE_ACCESS" :
					method == (FILE_READ_ACCESS | FILE_WRITE_ACCESS) ? "FILE_READ_ACCESS | FILE_WRITE_ACCESS" :
					"INVALID_ACCESS";

				_logger->info("- Code: {:#8x}  Macro: CTL_CODE({:#4x}, {:#3x}, {}, {})",
					code,
					deviceType,
					function,
					methodName,
					accessName
				);
			}
		}
#endif
		break;
	}
	return TRUE;
}
