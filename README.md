# cloudscan

## Introduction

A simple python library to wrap the [minidbg](https://github.com/ryu0886/minidbg) tool. 
It's also a simple web API implemented by Flask which is powered by the IIS on Windows 11.
With the limited resource so we at most run the executable for [60](https://github.com/ryu0886/cloudscan/blob/main/core/sample.py#L60) seconds. 
The final result will be a JSON object. For example:

```
{
    "loader_pid": 2764,
    "sample_pid": 5760,
    "sample_image": "C:\\inetpub\\cloudscan\\upload\\4834e159-f0f3-11ee-a2a0-00155d8a070b\\55207d137969974c814134ae41915dcd.exe",
    "sample_sha256": "4f3156e1af647db77781b21aa701e390f28fb08818bd6e673806b97c8b395930",
    "all_records": {
        "5760": {
            "ppid": 2764,
            "pid": 5760,
            "image": "C:\\inetpub\\cloudscan\\upload\\4834e159-f0f3-11ee-a2a0-00155d8a070b\\55207d137969974c814134ae41915dcd.exe",
            "basename": "55207d137969974c814134ae41915dcd.exe",
            "sha256": "4f3156e1af647db77781b21aa701e390f28fb08818bd6e673806b97c8b395930",
            "api_count": {
                "ntdll.dll!NtProtectVirtualMemory": 436,
                "ntdll.dll!NtCreateEvent": 39,
                "ntdll.dll!NtOpenKey": 135,
                "ntdll.dll!NtOpenFile": 42,
                "ntdll.dll!NtOpenSection": 64,
                "ntdll.dll!LdrGetProcedureAddressForCaller": 133,
                "ntdll.dll!LdrLoadDll": 19,
                "ntdll.dll!LdrGetProcedureAddress": 34,
                "ntdll.dll!NtOpenKeyEx": 171,
                "ntdll.dll!NtCreateSection": 21,
                "ntdll.dll!NtOpenProcessToken": 4,
                "ntdll.dll!NtCreateMutant": 2,
                "ntdll.dll!NtOpenSemaphore": 2,
                "ntdll.dll!LdrGetDllHandle": 22,
                "ntdll.dll!NtCreateSemaphore": 10,
                "ntdll.dll!CsrClientCallServer": 2,
                "ntdll.dll!NtAlpcSendWaitReceivePort": 2,
                "ntdll.dll!NtOpenEvent": 2,
                "ntdll.dll!RtlCreateUnicodeStringFromAsciiz": 1,
                "kernel32.dll!LoadLibraryW": 4,
                "ntdll.dll!RtlCreateUnicodeString": 1,
                "ntdll.dll!NtCreateFile": 2
            },
            "behavior": []
        }
    }
}
```
