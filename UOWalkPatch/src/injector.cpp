#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <iostream>

static DWORD FindProcess(const std::wstring& name) {
    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe{ sizeof(pe) };
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name.c_str()) == 0) { pid = pe.th32ProcessID; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

static bool InjectHandle(HANDLE hProc, const std::wstring& dllPath) {
    SIZE_T size = (dllPath.size() + 1) * sizeof(wchar_t);
    LPVOID mem = VirtualAllocEx(hProc, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem)
        return false;

    if (!WriteProcessMemory(hProc, mem, dllPath.c_str(), size, nullptr)) {
        VirtualFreeEx(hProc, mem, 0, MEM_RELEASE);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(
        hProc, nullptr, 0,
        (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), L"LoadLibraryW"),
        mem, 0, nullptr);
    if (!hThread) {
        VirtualFreeEx(hProc, mem, 0, MEM_RELEASE);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);
    VirtualFreeEx(hProc, mem, 0, MEM_RELEASE);
    CloseHandle(hThread);
    return true;
}

static bool Inject(DWORD pid, const std::wstring& dllPath) {
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc)
        return false;
    bool ok = InjectHandle(hProc, dllPath);
    CloseHandle(hProc);
    return ok;
}

int wmain(int argc, wchar_t* argv[]) {
    std::wstring dllPath = L"UOWalkPatch.dll";
    if (argc > 1)
        dllPath = argv[1];

    DWORD pid = FindProcess(L"UOSA.exe");
    HANDLE hProc = nullptr;
    HANDLE hThread = nullptr;
    bool launched = false;

    if (!pid) {
        const wchar_t* exePath = L"C:\\Program Files (x86)\\Electronic Arts\\Ultima Online Enhanced\\UOSA.exe";
        STARTUPINFOW si{ sizeof(si) };
        PROCESS_INFORMATION pi{};
        if (!CreateProcessW(exePath, nullptr, nullptr, nullptr, FALSE,
            CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
            std::wcerr << L"Failed to launch UOSA.exe" << std::endl;
            return 1;
        }
        pid = pi.dwProcessId;
        hProc = pi.hProcess;
        hThread = pi.hThread;
        launched = true;
    } else {
        hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProc) {
            std::wcerr << L"Failed to open UOSA.exe" << std::endl;
            return 1;
        }
    }

    bool ok = InjectHandle(hProc, dllPath);

    if (launched && hThread) {
        ResumeThread(hThread);
        CloseHandle(hThread);
    }

    CloseHandle(hProc);

    if (!ok) {
        std::wcerr << L"Injection failed" << std::endl;
        return 1;
    }

    if (launched)
        std::wcout << L"UOSA.exe launched and injected" << std::endl;
    else
        std::wcout << L"Injected" << std::endl;
    return 0;
}
