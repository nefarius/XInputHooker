//
// WinAPI
// 
#define WIN32_LEAN_AND_MEAN
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


static BOOL(WINAPI* real_SetupDiEnumDeviceInterfaces)(HDEVINFO, PSP_DEVINFO_DATA, const GUID*, DWORD, PSP_DEVICE_INTERFACE_DATA) = SetupDiEnumDeviceInterfaces;
static BOOL(WINAPI* real_DeviceIoControl)(HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED) = DeviceIoControl;
static HANDLE(WINAPI* real_CreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = CreateFileA;
static HANDLE(WINAPI* real_CreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = CreateFileW;


//
// Hooks SetupDiEnumDeviceInterfaces() API
// 
BOOL WINAPI DetourSetupDiEnumDeviceInterfaces(
	HDEVINFO                  DeviceInfoSet,
	PSP_DEVINFO_DATA          DeviceInfoData,
	const GUID* InterfaceClassGuid,
	DWORD                     MemberIndex,
	PSP_DEVICE_INTERFACE_DATA DeviceInterfaceData
)
{
	std::shared_ptr<spdlog::logger> _logger = spdlog::get("XInputHooker")->clone("SetupDiEnumDeviceInterfaces");
	
	auto retval = real_SetupDiEnumDeviceInterfaces(DeviceInfoSet, DeviceInfoData, InterfaceClassGuid, MemberIndex, DeviceInterfaceData);

	_logger->info("InterfaceClassGuid = {{{0:X}-{1:X}-{2:X}-{3:X}{4:X}-{5:X}{6:X}{7:X}{8:X}{9:X}{10:X}}}, " \
		"return = 0x{11:X}, error = 0x{12:X}",
		InterfaceClassGuid->Data1, InterfaceClassGuid->Data2, InterfaceClassGuid->Data3,
		InterfaceClassGuid->Data4[0], InterfaceClassGuid->Data4[1], InterfaceClassGuid->Data4[2], InterfaceClassGuid->Data4[3],
		InterfaceClassGuid->Data4[4], InterfaceClassGuid->Data4[5], InterfaceClassGuid->Data4[6], InterfaceClassGuid->Data4[7],
		retval, GetLastError());

	return retval;
}

//
// Hooks CreateFileA() API
// 
HANDLE WINAPI DetourCreateFileA(
	LPCSTR                lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
)
{
	std::shared_ptr<spdlog::logger> _logger = spdlog::get("XInputHooker")->clone("CreateFileA");
	std::string path(lpFileName);

	if (path.rfind("\\\\", 0) == 0)
		_logger->info("lpFileName = {}", path);

	return real_CreateFileA(
		lpFileName,
		dwDesiredAccess,
		dwShareMode,
		lpSecurityAttributes,
		dwCreationDisposition,
		dwFlagsAndAttributes,
		hTemplateFile
	);
}

//
// Hooks CreateFileW() API
// 
HANDLE WINAPI DetourCreateFileW(
	LPCWSTR               lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
)
{
	std::shared_ptr<spdlog::logger> _logger = spdlog::get("XInputHooker")->clone("CreateFileW");
	std::string path(strconverter.to_bytes(lpFileName));

	if (path.rfind("\\\\", 0) == 0)
		_logger->info("lpFileName = {}", path);

	return real_CreateFileW(
		lpFileName,
		dwDesiredAccess,
		dwShareMode,
		lpSecurityAttributes,
		dwCreationDisposition,
		dwFlagsAndAttributes,
		hTemplateFile
	);
}

//
// Hooks DeviceIoControl() API
// 
BOOL WINAPI DetourDeviceIoControl(
	HANDLE       hDevice,
	DWORD        dwIoControlCode,
	LPVOID       lpInBuffer,
	DWORD        nInBufferSize,
	LPVOID       lpOutBuffer,
	DWORD        nOutBufferSize,
	LPDWORD      lpBytesReturned,
	LPOVERLAPPED lpOverlapped
)
{
	std::shared_ptr<spdlog::logger> _logger = spdlog::get("XInputHooker")->clone("DeviceIoControl");
	const PUCHAR charInBuf = (PUCHAR)lpInBuffer;
	const std::vector<char> inBuffer(charInBuf, charInBuf + nInBufferSize);

	switch (dwIoControlCode)
	{
	case IOCTL_XUSB_GET_INFORMATION:
		_logger->info("[I] [IOCTL_XUSB_GET_INFORMATION]              {:Xpn}", spdlog::to_hex(inBuffer));
		break;
	case IOCTL_XUSB_GET_CAPABILITIES:
		_logger->info("[I] [IOCTL_XUSB_GET_CAPABILITIES]             {:Xpn}", spdlog::to_hex(inBuffer));
		break;
	case IOCTL_XUSB_GET_LED_STATE:
		_logger->info("[I] [IOCTL_XUSB_GET_LED_STATE]                {:Xpn}", spdlog::to_hex(inBuffer));
		break;
	case IOCTL_XUSB_GET_STATE:
		_logger->info("[I] [IOCTL_XUSB_GET_STATE]                    {:Xpn}", spdlog::to_hex(inBuffer));
		break;
	case IOCTL_XUSB_SET_STATE:
		_logger->info("[I] [IOCTL_XUSB_SET_STATE]                    {:Xpn}", spdlog::to_hex(inBuffer));
		break;
	case IOCTL_XUSB_WAIT_GUIDE_BUTTON:
		_logger->info("[I] [IOCTL_XUSB_WAIT_GUIDE_BUTTON]            {:Xpn}", spdlog::to_hex(inBuffer));
		break;
	case IOCTL_XUSB_GET_BATTERY_INFORMATION:
		_logger->info("[I] [IOCTL_XUSB_GET_BATTERY_INFORMATION]      {:Xpn}", spdlog::to_hex(inBuffer));
		break;
	case IOCTL_XUSB_POWER_DOWN:
		_logger->info("[I] [IOCTL_XUSB_POWER_DOWN]                   {:Xpn}", spdlog::to_hex(inBuffer));
		break;
	case IOCTL_XUSB_GET_AUDIO_DEVICE_INFORMATION:
		_logger->info("[I] [IOCTL_XUSB_GET_AUDIO_DEVICE_INFORMATION] {:Xpn}", spdlog::to_hex(inBuffer));
		break;
	case IOCTL_XUSB_WAIT_FOR_INPUT:
		_logger->info("[I] [IOCTL_XUSB_WAIT_FOR_INPUT]               {:Xpn}", spdlog::to_hex(inBuffer));
		break;
	case IOCTL_XUSB_GET_INFORMATION_EX:
		_logger->info("[I] [IOCTL_XUSB_GET_INFORMATION_EX]           {:Xpn}", spdlog::to_hex(inBuffer));
		break;
	default:
		_logger->warn("Unknown I/O control code: 0x{:X} -> {:Xpn}", dwIoControlCode, spdlog::to_hex(inBuffer));
		break;
	}

	auto retval = real_DeviceIoControl(
		hDevice,
		dwIoControlCode,
		lpInBuffer,
		nInBufferSize,
		lpOutBuffer,
		nOutBufferSize,
		lpBytesReturned,
		lpOverlapped
	);

	if (nOutBufferSize > 0)
	{
		const PUCHAR charOutBuf = (PUCHAR)lpOutBuffer;
		const std::vector<char> outBuffer(charOutBuf, charOutBuf + *lpBytesReturned);

		switch (dwIoControlCode)
		{
		case IOCTL_XUSB_GET_INFORMATION:
			_logger->info("[O] [IOCTL_XUSB_GET_INFORMATION]              {:Xpn}", spdlog::to_hex(outBuffer));
			break;
		case IOCTL_XUSB_GET_CAPABILITIES:
			_logger->info("[O] [IOCTL_XUSB_GET_CAPABILITIES]             {:Xpn}", spdlog::to_hex(outBuffer));
			break;
		case IOCTL_XUSB_GET_LED_STATE:
			_logger->info("[O] [IOCTL_XUSB_GET_LED_STATE]                {:Xpn}", spdlog::to_hex(outBuffer));
			break;
		case IOCTL_XUSB_GET_STATE:
			_logger->info("[O] [IOCTL_XUSB_GET_STATE]                    {:Xpn}", spdlog::to_hex(outBuffer));
			break;
		case IOCTL_XUSB_SET_STATE:
			_logger->info("[O] [IOCTL_XUSB_SET_STATE]                    {:Xpn}", spdlog::to_hex(outBuffer));
			break;
		case IOCTL_XUSB_WAIT_GUIDE_BUTTON:
			_logger->info("[O] [IOCTL_XUSB_WAIT_GUIDE_BUTTON]            {:Xpn}", spdlog::to_hex(outBuffer));
			break;
		case IOCTL_XUSB_GET_BATTERY_INFORMATION:
			_logger->info("[O] [IOCTL_XUSB_GET_BATTERY_INFORMATION]      {:Xpn}", spdlog::to_hex(outBuffer));
			break;
		case IOCTL_XUSB_POWER_DOWN:
			_logger->info("[O] [IOCTL_XUSB_POWER_DOWN]                   {:Xpn}", spdlog::to_hex(outBuffer));
			break;
		case IOCTL_XUSB_GET_AUDIO_DEVICE_INFORMATION:
			_logger->info("[O] [IOCTL_XUSB_GET_AUDIO_DEVICE_INFORMATION] {:Xpn}", spdlog::to_hex(outBuffer));
			break;
		case IOCTL_XUSB_WAIT_FOR_INPUT:
			_logger->info("[O] [IOCTL_XUSB_WAIT_FOR_INPUT]               {:Xpn}", spdlog::to_hex(outBuffer));
			break;
		case IOCTL_XUSB_GET_INFORMATION_EX:
			_logger->info("[O] [IOCTL_XUSB_GET_INFORMATION_EX]           {:Xpn}", spdlog::to_hex(outBuffer));
			break;
		default:
			break;
		}
	}

	return retval;
}

EXTERN_C IMAGE_DOS_HEADER __ImageBase;

BOOL WINAPI DllMain(HINSTANCE dll_handle, DWORD reason, LPVOID reserved)
{
	if (DetourIsHelperProcess()) {
		return TRUE;
	}

	switch (reason) {
	case DLL_PROCESS_ATTACH:
	{
		CHAR dllPath[MAX_PATH];
			
		GetModuleFileNameA((HINSTANCE)&__ImageBase, dllPath, MAX_PATH);
		PathRemoveFileSpecA(dllPath);

		auto logger = spdlog::basic_logger_mt(
			"XInputHooker",
			std::string(dllPath) + "\\XInputHooker.log"
		);

#if _DEBUG
		spdlog::set_level(spdlog::level::debug);
		logger->flush_on(spdlog::level::debug);
#else
		logger->flush_on(spdlog::level::info);
#endif

		spdlog::set_default_logger(logger);
	}

	DisableThreadLibraryCalls(dll_handle);
	DetourRestoreAfterWith();

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID)real_SetupDiEnumDeviceInterfaces, DetourSetupDiEnumDeviceInterfaces);
	DetourAttach(&(PVOID)real_DeviceIoControl, DetourDeviceIoControl);
	DetourAttach(&(PVOID)real_CreateFileA, DetourCreateFileA);
	DetourAttach(&(PVOID)real_CreateFileW, DetourCreateFileW);
	DetourTransactionCommit();

	break;

	case DLL_PROCESS_DETACH:
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourDetach(&(PVOID)real_SetupDiEnumDeviceInterfaces, DetourSetupDiEnumDeviceInterfaces);
		DetourDetach(&(PVOID)real_DeviceIoControl, DetourDeviceIoControl);
		DetourDetach(&(PVOID)real_CreateFileA, DetourCreateFileA);
		DetourDetach(&(PVOID)real_CreateFileW, DetourCreateFileW);
		DetourTransactionCommit();
		break;
	}
	return TRUE;
}
