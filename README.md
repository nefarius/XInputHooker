# XInputHooker

XInput reverse-engineering tools and documentation

[![Build status](https://ci.appveyor.com/api/projects/status/sifndeu76a3wevof?svg=true)](https://ci.appveyor.com/project/nefarius/xinputhooker)

## About

This DLL project hooks common Windows APIs used internally by XInput libraries. Compatible device discovery is actually rather primitive, [`SetupDiEnumDeviceInterfaces`](https://docs.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupdienumdeviceinterfaces) is called on the XUSB device interface GUID (see `XUSB.h`), on success device handle is obtained via [`CreateFile`](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea) and data exchanged using [`DeviceIoControl`](https://docs.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-deviceiocontrol). Said APIs get hooked and the arguments of interest dumped into a log file.

## Build

[Follow the Vcpkg Quick Start](https://github.com/Microsoft/vcpkg#quick-start) and install the following packages:

- `.\vcpkg install spdlog:x86-windows-static spdlog:x64-windows-static detours:x86-windows-static detours:x64-windows-static jsoncpp:x86-windows-static jsoncpp:x64-windows-static`

## Use

Build or download the `XInputHooker.dll` for the right architecture (32-Bit for 32-Bit processes and likewise for 64-Bit) and place the [`ioctls.json`](./XInputHooker/ioctls.json) file in the same directory as the DLL. [Inject](https://github.com/nefarius/Injector) the `XInputHooker.dll` into a process/game using any variant of the XInput user API libraries. Upon successful injection a `XInputHooker.log` will be generated in the process root directory. All sniffed API calls will be dumped there. It will grow fast so don't run for too long 😉

## Download

### Latest CI builds

Note: AppVeyor artifacts expire after 1 month, so the links might not work if no new build has happened ever since.

### x86

- [XInputHooker.dll](https://ci.appveyor.com/api/projects/nefarius/XInputHooker/artifacts/bin/x86/XInputHooker.dll?job=Platform%3A%20x86)

### x64

- [XInputHooker.dll](https://ci.appveyor.com/api/projects/nefarius/XInputHooker/artifacts/bin/x64/XInputHooker.dll?job=Platform%3A%20x64)
