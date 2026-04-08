#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <regex>
#include <algorithm>
#include <iomanip>
#include <sstream>

#define READ_CHUNK_SIZE (1 * 1024 * 1024)
#define MAX_THREADS 8
#define HEXDUMP_WIDTH 16
#define MAX_DUMP_SIZE 1024

std::mutex g_mutex;
std::atomic<bool> g_shouldExit(false);

bool EnableDebugPrivilege() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;

    TOKEN_PRIVILEGES tkp = { 1 };
    bool success = LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid) &&
        AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL);
    CloseHandle(hToken);
    return success && (GetLastError() == ERROR_SUCCESS);
}

std::vector<DWORD> GetPIDs(const char* processName) {
    std::vector<DWORD> pids;
    PROCESSENTRY32 pe = { sizeof(PROCESSENTRY32) };

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return pids;

    char exeName[260];
    for (BOOL success = Process32First(hSnap, &pe); success && !g_shouldExit; success = Process32Next(hSnap, &pe)) {
        WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, exeName, sizeof(exeName), NULL, NULL);
        if (_stricmp(exeName, processName) == 0) {
            pids.push_back(pe.th32ProcessID);
        }
    }
    CloseHandle(hSnap);
    return pids;
}

void PrintHexDump(HANDLE hProc, LPCVOID baseAddr, LPCVOID startAddr, LPCVOID endAddr) {
    const size_t startOffset = (size_t)startAddr - (size_t)baseAddr;
    const size_t rangeSize = (size_t)endAddr - (size_t)startAddr;

    if (rangeSize == 0) {
        return;
    }

    size_t dumpSize = min(rangeSize, (size_t)MAX_DUMP_SIZE);
    std::vector<BYTE> buffer(dumpSize);

    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProc, startAddr, buffer.data(), dumpSize, &bytesRead)) {
        DWORD err = GetLastError();

        printf("[!] ReadProcessMemory FAILED\n");
        printf("    Address: %p\n", startAddr);
        printf("    Size   : %zu\n", dumpSize);
        printf("    Error  : %lu\n", err);

        return;
    }

    printf("Address                                                                  ASCII\n");
    printf("---------------   ------------------------------------------------  ----------------\n");

    for (size_t offset = 0; offset < bytesRead; offset += HEXDUMP_WIDTH) {
        size_t lineLength = min(HEXDUMP_WIDTH, bytesRead - offset);
        LPCVOID currentAddr = (LPCVOID)((size_t)startAddr + offset);

        // Print actual memory address
        printf("%p  ", currentAddr);

        // Hex bytes
        for (size_t i = 0; i < HEXDUMP_WIDTH; i++) {
            if (i < lineLength) {
                printf("%02x ", buffer[offset + i]);
            }
            else {
                printf("   ");
            }
            if (i == 7) printf(" ");
        }

        // ASCII
        printf(" ");
        for (size_t i = 0; i < HEXDUMP_WIDTH; i++) {
            if (i < lineLength) {
                unsigned char c = buffer[offset + i];
                printf("%c", (c >= 32 && c <= 126) ? c : '.');
            }
            else {
                printf(" ");
            }
        }
        printf("\n");
    }
    printf("---------------   ------------------------------------------------  ----------------\n");
}

void DumpReferencedMemory(HANDLE hOriginalProc, const std::wstring& processName, DWORD pid,
    const std::wstring& startAddrStr, const std::wstring& endAddrStr) {
    char narrowName[256];
    WideCharToMultiByte(CP_ACP, 0, processName.c_str(), -1, narrowName, sizeof(narrowName), NULL, NULL);


    printf("\nProcess --> %s\n", narrowName);
    printf("PID --> %lu\n", pid);
    printf("Memory Range --> 0x%ls - 0x%ls\n\n", startAddrStr.c_str(), endAddrStr.c_str());

    try {
        LPCVOID startAddr = reinterpret_cast<LPCVOID>(std::stoull(startAddrStr, nullptr, 16));
        LPCVOID endAddr = reinterpret_cast<LPCVOID>(std::stoull(endAddrStr, nullptr, 16));

        // Get the base address of the region containing this memory
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(hOriginalProc, startAddr, &mbi, sizeof(mbi))) {
            PrintHexDump(hOriginalProc, mbi.AllocationBase, startAddr, endAddr);
        }
    }
    catch (...) {
    }
}

void ScanChunk(HANDLE hProc, const BYTE* buffer, SIZE_T size, LPCVOID baseAddr) {
    const wchar_t* wbuf = reinterpret_cast<const wchar_t*>(buffer);
    size_t wsize = size / sizeof(wchar_t);

    static const std::wregex pattern(
        L"([a-zA-Z0-9_]+\\.exe)\\s*\\((\\d+)\\)\\s*\\(0x([a-fA-F0-9]+)\\s*-\\s*0x([a-fA-F0-9]+)\\)",
        std::regex::optimize
    );

    const wchar_t* end = wbuf + wsize;
    for (const wchar_t* p = wbuf; p < end - 4 && !g_shouldExit; p++) {
        if (p[0] == L'.' && p[1] == L'e' && p[2] == L'x' && p[3] == L'e') {
            const wchar_t* start = p;
            while (start > wbuf && *start != L'\0') start--;
            if (*start == L'\0') start++;

            const wchar_t* str_end = p;
            while (str_end < end && *str_end != L'\0') str_end++;

            std::wcmatch match;
            if (std::regex_search(start, str_end, match, pattern)) {
                std::lock_guard<std::mutex> lock(g_mutex);

                DumpReferencedMemory(hProc,
                    match[1].str(),
                    std::stoul(match[2].str()),
                    match[3].str(),
                    match[4].str());
            }
            p = str_end;
        }
    }
}

void MemoryScannerWorker(HANDLE hProc, LPCVOID startAddr, LPCVOID endAddr) {
    std::vector<BYTE> buffer(READ_CHUNK_SIZE);
    LPCVOID currentAddr = startAddr;

    while (currentAddr < endAddr && !g_shouldExit) {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQueryEx(hProc, currentAddr, &mbi, sizeof(mbi)))
            break;

        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
            SIZE_T remaining = mbi.RegionSize;
            LPCVOID regionAddr = mbi.BaseAddress;

            while (remaining > 0 && !g_shouldExit) {
                SIZE_T chunkSize = min(remaining, READ_CHUNK_SIZE);
                SIZE_T bytesRead = 0;

                if (ReadProcessMemory(hProc, regionAddr, buffer.data(), chunkSize, &bytesRead) && bytesRead > 0) {
                    ScanChunk(hProc, buffer.data(), bytesRead, regionAddr);
                }

                remaining -= chunkSize;
                regionAddr = reinterpret_cast<LPCVOID>(reinterpret_cast<size_t>(regionAddr) + chunkSize);
            }
        }

        currentAddr = reinterpret_cast<LPCVOID>(reinterpret_cast<size_t>(mbi.BaseAddress) + mbi.RegionSize);
    }
}

void ScanProcess(DWORD pid, const char* procName) {
    HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) {
        return;
    }

    SYSTEM_INFO si;
    GetSystemInfo(&si);

    // Split the work across threads
    const size_t addressRange = reinterpret_cast<size_t>(si.lpMaximumApplicationAddress) -
        reinterpret_cast<size_t>(si.lpMinimumApplicationAddress);
    const size_t chunkSize = addressRange / MAX_THREADS;

    std::vector<std::thread> threads;
    for (int i = 0; i < MAX_THREADS; i++) {
        LPCVOID start = reinterpret_cast<LPCVOID>(
            reinterpret_cast<size_t>(si.lpMinimumApplicationAddress) + i * chunkSize);
        LPCVOID end = reinterpret_cast<LPCVOID>(
            reinterpret_cast<size_t>(start) + chunkSize);

        threads.emplace_back(MemoryScannerWorker, hProc, start, end);
    }

    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }

    CloseHandle(hProc);
}

int main() {
    if (!EnableDebugPrivilege()) {
        return 1;
    }

    const char* targets[] = { "dwm.exe", "Ctfmon.exe", "Explorer.exe", "Taskhostw.exe" };

    for (const char* target : targets) {
        auto pids = GetPIDs(target);
        for (DWORD pid : pids) {
            ScanProcess(pid, target);
        }
    }

    return 0;
}