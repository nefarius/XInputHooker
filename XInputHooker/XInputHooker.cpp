// XInputHooker.cpp : Defines the entry point for the console application.
//

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <SetupAPI.h>
#include <initguid.h>
#include <winioctl.h>
#include "XUSB.h"

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


static BOOL(WINAPI* real_SetupDiEnumDeviceInterfaces)(HDEVINFO, PSP_DEVINFO_DATA, const GUID*, DWORD, PSP_DEVICE_INTERFACE_DATA) = SetupDiEnumDeviceInterfaces;
static BOOL(WINAPI* real_DeviceIoControl)(HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED) = DeviceIoControl;


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
	auto retval = real_SetupDiEnumDeviceInterfaces(DeviceInfoSet, DeviceInfoData, InterfaceClassGuid, MemberIndex, DeviceInterfaceData);

	spdlog::info("SetupDiEnumDeviceInterfaces: InterfaceClassGuid = {{{0:X}-{1:X}-{2:X}-{3:X}{4:X}-{5:X}{6:X}{7:X}{8:X}{9:X}{10:X}}}, " \
		"return = 0x{11:X}, error = 0x{12:X}",
		InterfaceClassGuid->Data1, InterfaceClassGuid->Data2, InterfaceClassGuid->Data3,
		InterfaceClassGuid->Data4[0], InterfaceClassGuid->Data4[1], InterfaceClassGuid->Data4[2], InterfaceClassGuid->Data4[3],
		InterfaceClassGuid->Data4[4], InterfaceClassGuid->Data4[5], InterfaceClassGuid->Data4[6], InterfaceClassGuid->Data4[7],
		retval, GetLastError());

	return retval;
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
	const PUCHAR charInBuf = (PUCHAR)lpInBuffer;
	const std::vector<char> inBuffer(charInBuf, charInBuf + nInBufferSize);

	switch (dwIoControlCode)
	{
	case IOCTL_XUSB_GET_INFORMATION:
		spdlog::info("[I] [IOCTL_XUSB_GET_INFORMATION]              {:Xpn}", spdlog::to_hex(inBuffer));
		break;
	case IOCTL_XUSB_GET_CAPABILITIES:
		spdlog::info("[I] [IOCTL_XUSB_GET_CAPABILITIES]             {:Xpn}", spdlog::to_hex(inBuffer));
		break;
	case IOCTL_XUSB_GET_LED_STATE:
		spdlog::info("[I] [IOCTL_XUSB_GET_LED_STATE]                {:Xpn}", spdlog::to_hex(inBuffer));
		break;
	case IOCTL_XUSB_GET_STATE:
		spdlog::info("[I] [IOCTL_XUSB_GET_STATE]                    {:Xpn}", spdlog::to_hex(inBuffer));
		break;
	case IOCTL_XUSB_SET_STATE:
		spdlog::info("[I] [IOCTL_XUSB_SET_STATE]                    {:Xpn}", spdlog::to_hex(inBuffer));
		break;
	case IOCTL_XUSB_WAIT_GUIDE_BUTTON:
		spdlog::info("[I] [IOCTL_XUSB_WAIT_GUIDE_BUTTON]            {:Xpn}", spdlog::to_hex(inBuffer));
		break;
	case IOCTL_XUSB_GET_BATTERY_INFORMATION:
		spdlog::info("[I] [IOCTL_XUSB_GET_BATTERY_INFORMATION]      {:Xpn}", spdlog::to_hex(inBuffer));
		break;
	case IOCTL_XUSB_POWER_DOWN:
		spdlog::info("[I] [IOCTL_XUSB_POWER_DOWN]                   {:Xpn}", spdlog::to_hex(inBuffer));
		break;
	case IOCTL_XUSB_GET_AUDIO_DEVICE_INFORMATION:
		spdlog::info("[I] [IOCTL_XUSB_GET_AUDIO_DEVICE_INFORMATION] {:Xpn}", spdlog::to_hex(inBuffer));
		break;
	case IOCTL_XUSB_WAIT_FOR_INPUT:
		spdlog::info("[I] [IOCTL_XUSB_WAIT_FOR_INPUT]               {:Xpn}", spdlog::to_hex(inBuffer));
		break;
	case IOCTL_XUSB_GET_INFORMATION_EX:
		spdlog::info("[I] [IOCTL_XUSB_GET_INFORMATION_EX]           {:Xpn}", spdlog::to_hex(inBuffer));
		break;
	default:
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

	const PUCHAR charOutBuf = (PUCHAR)lpOutBuffer;
	const std::vector<char> outBuffer(charOutBuf, charOutBuf + *lpBytesReturned);

	switch (dwIoControlCode)
	{
	case IOCTL_XUSB_GET_INFORMATION:
		spdlog::info("[O] [IOCTL_XUSB_GET_INFORMATION]              {:Xpn}", spdlog::to_hex(outBuffer));
		break;
	case IOCTL_XUSB_GET_CAPABILITIES:
		spdlog::info("[O] [IOCTL_XUSB_GET_CAPABILITIES]             {:Xpn}", spdlog::to_hex(outBuffer));
		break;
	case IOCTL_XUSB_GET_LED_STATE:
		spdlog::info("[O] [IOCTL_XUSB_GET_LED_STATE]                {:Xpn}", spdlog::to_hex(outBuffer));
		break;
	case IOCTL_XUSB_GET_STATE:
		spdlog::info("[O] [IOCTL_XUSB_GET_STATE]                    {:Xpn}", spdlog::to_hex(outBuffer));
		break;
	case IOCTL_XUSB_SET_STATE:
		spdlog::info("[O] [IOCTL_XUSB_SET_STATE]                    {:Xpn}", spdlog::to_hex(outBuffer));
		break;
	case IOCTL_XUSB_WAIT_GUIDE_BUTTON:
		spdlog::info("[O] [IOCTL_XUSB_WAIT_GUIDE_BUTTON]            {:Xpn}", spdlog::to_hex(outBuffer));
		break;
	case IOCTL_XUSB_GET_BATTERY_INFORMATION:
		spdlog::info("[O] [IOCTL_XUSB_GET_BATTERY_INFORMATION]      {:Xpn}", spdlog::to_hex(outBuffer));
		break;
	case IOCTL_XUSB_POWER_DOWN:
		spdlog::info("[O] [IOCTL_XUSB_POWER_DOWN]                   {:Xpn}", spdlog::to_hex(outBuffer));
		break;
	case IOCTL_XUSB_GET_AUDIO_DEVICE_INFORMATION:
		spdlog::info("[O] [IOCTL_XUSB_GET_AUDIO_DEVICE_INFORMATION] {:Xpn}", spdlog::to_hex(outBuffer));
		break;
	case IOCTL_XUSB_WAIT_FOR_INPUT:
		spdlog::info("[O] [IOCTL_XUSB_WAIT_FOR_INPUT]               {:Xpn}", spdlog::to_hex(outBuffer));
		break;
	case IOCTL_XUSB_GET_INFORMATION_EX:
		spdlog::info("[O] [IOCTL_XUSB_GET_INFORMATION_EX]           {:Xpn}", spdlog::to_hex(outBuffer));
		break;
	default:
		break;
	}

	return retval;
}

BOOL WINAPI DllMain(HINSTANCE dll_handle, DWORD reason, LPVOID reserved)
{
	if (DetourIsHelperProcess()) {
		return TRUE;
	}

	switch (reason) {
	case DLL_PROCESS_ATTACH:
	{
		auto logger = spdlog::basic_logger_mt(
			"XInputHooker",
			"XInputHooker.log"
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
	DetourTransactionCommit();

	break;

	case DLL_PROCESS_DETACH:
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourDetach(&(PVOID)real_SetupDiEnumDeviceInterfaces, DetourSetupDiEnumDeviceInterfaces);
		DetourDetach(&(PVOID)real_DeviceIoControl, DetourDeviceIoControl);
		DetourTransactionCommit();
		break;
	}
	return TRUE;
}
