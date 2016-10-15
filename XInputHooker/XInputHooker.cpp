// XInputHooker.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>
#include <SetupAPI.h>
#include <Xinput.h>
#include "MinHook.h"

typedef VOID(WINAPI *XInputEnable_t)(BOOL);
typedef DWORD(WINAPI *XInputGetState_t)(DWORD, XINPUT_STATE *);

typedef BOOL(WINAPI *SetupDiEnumDeviceInterfaces_t)(HDEVINFO, PSP_DEVINFO_DATA, const GUID *, DWORD, PSP_DEVICE_INTERFACE_DATA);
typedef BOOL(WINAPI *DeviceIoControl_t)(HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);

SetupDiEnumDeviceInterfaces_t fpSetupDiEnumDeviceInterfaces = nullptr;
DeviceIoControl_t fpDeviceIoControl = nullptr;

FILE *fLog = nullptr;
unsigned long counter = 0;

BOOL DetourSetupDiEnumDeviceInterfaces(
    HDEVINFO                  DeviceInfoSet,
    PSP_DEVINFO_DATA          DeviceInfoData,
    const GUID                *InterfaceClassGuid,
    DWORD                     MemberIndex,
    PSP_DEVICE_INTERFACE_DATA DeviceInterfaceData
)
{
    printf("GUID = {%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX}\n",
        InterfaceClassGuid->Data1, InterfaceClassGuid->Data2, InterfaceClassGuid->Data3,
        InterfaceClassGuid->Data4[0], InterfaceClassGuid->Data4[1], InterfaceClassGuid->Data4[2], InterfaceClassGuid->Data4[3],
        InterfaceClassGuid->Data4[4], InterfaceClassGuid->Data4[5], InterfaceClassGuid->Data4[6], InterfaceClassGuid->Data4[7]);

    return fpSetupDiEnumDeviceInterfaces(DeviceInfoSet, DeviceInfoData, InterfaceClassGuid, MemberIndex, DeviceInterfaceData);
}

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
    auto inBuffer = static_cast<PUCHAR>(lpInBuffer);
    auto packetCount = counter++;

    fprintf(fLog, "\n[%010lu] [%08lu] [%08lu] [I] - ", packetCount, dwIoControlCode, nInBufferSize);

    for (auto i = 0; i < nInBufferSize; i++)
    {
        fprintf(fLog, "%02X ", inBuffer[i]);
    }

    auto retval = fpDeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesReturned, lpOverlapped);

    auto outBuffer = static_cast<PUCHAR>(lpOutBuffer);

    fprintf(fLog, "\n[%010lu] [%08lu] [%08lu] [O] - ", packetCount, dwIoControlCode, *lpBytesReturned);

    for (auto i = 0; i < *lpBytesReturned; i++)
    {
        fprintf(fLog, "%02X ", outBuffer[i]);
    }

    return retval;
}


template <typename T>
inline MH_STATUS MH_CreateHookEx(LPVOID pTarget, LPVOID pDetour, T** ppOriginal)
{
    return MH_CreateHook(pTarget, pDetour, reinterpret_cast<LPVOID*>(ppOriginal));
}

template <typename T>
inline MH_STATUS MH_CreateHookApiEx(
    LPCWSTR pszModule, LPCSTR pszProcName, LPVOID pDetour, T** ppOriginal)
{
    return MH_CreateHookApi(
        pszModule, pszProcName, pDetour, reinterpret_cast<LPVOID*>(ppOriginal));
}

int main()
{
    fopen_s(&fLog, "xinput.log", "wt");
    fprintf(fLog, "Time stamp, I/O control code, buffer size, input or output\n");

    // Initialize MinHook.
    if (MH_Initialize() != MH_OK)
    {
        return 1;
    }

    if (MH_CreateHook(&SetupDiEnumDeviceInterfaces, &DetourSetupDiEnumDeviceInterfaces,
        reinterpret_cast<LPVOID*>(&fpSetupDiEnumDeviceInterfaces)) != MH_OK)
    {
        return 1;
    }

    if (MH_EnableHook(&SetupDiEnumDeviceInterfaces) != MH_OK)
    {
        return 1;
    }

    if (MH_CreateHook(&DeviceIoControl, &DetourDeviceIoControl,
        reinterpret_cast<LPVOID*>(&fpDeviceIoControl)) != MH_OK)
    {
        return 1;
    }

    if (MH_EnableHook(&DeviceIoControl) != MH_OK)
    {
        return 1;
    }

    auto mod = LoadLibrary(L"xinput1_3.dll");
    auto enable = reinterpret_cast<XInputEnable_t>(GetProcAddress(mod, "XInputEnable"));
    auto getState = reinterpret_cast<XInputGetState_t>(GetProcAddress(mod, "XInputGetState"));

    enable(TRUE);
    XINPUT_STATE state;

    printf("XInputGetState = 0x%X\n", getState(0, &state));
    
    // Disable the hook for MessageBoxW.
    if (MH_DisableHook(MH_ALL_HOOKS) != MH_OK)
    {
        return 1;
    }

    // Uninitialize MinHook.
    if (MH_Uninitialize() != MH_OK)
    {
        return 1;
    }

    return 0;
}

