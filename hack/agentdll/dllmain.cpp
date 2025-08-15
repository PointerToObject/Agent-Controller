#include <windows.h>
#include <TlHelp32.h>
#include <thread>
#include <vector>


std::vector<unsigned long> ThreadID(unsigned long procID)
{
    std::vector<unsigned long> threadIDs;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0); 
    if (hSnap != INVALID_HANDLE_VALUE)
    {
        THREADENTRY32 th;
        th.dwSize = sizeof(th);
        if (Thread32First(hSnap, &th))
        {
            do {
                if (th.th32OwnerProcessID == procID)
                {
                    threadIDs.push_back(th.th32ThreadID);
                }
            } while (Thread32Next(hSnap, &th));
        }
        CloseHandle(hSnap);
    }

    return threadIDs;
}

unsigned __int64 FindPattern(char* base, unsigned int size, char* pattern, char* mask)
{
    size_t patternLength = strlen(mask);

    for (unsigned __int64 i = 0; i < size - patternLength; i++)
    {
        bool found = true;
        for (unsigned __int64 j = 0; j < patternLength; j++)
        {
            char c = *(char*)(base + i + j);

            if (mask[j] != '?' && pattern[j] != c)
            {
                found = false;
                break;
            }
        }

        if (found)
        {
            return (unsigned __int64)base + i;
        }
    }
    return 0;
}

struct BreakpointInfo
{
    HANDLE hPipe;
    BYTE* address;
    BYTE   originalByte;
};

static BreakpointInfo g_bpInfo = {}; // Still static, but you can set this before registering VEH

LONG WINAPI MyVehHandler(EXCEPTION_POINTERS* ExceptionInfo)
{
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT)
    {
        if ((BYTE*)ExceptionInfo->ContextRecord->Rip == g_bpInfo.address)
        {
            unsigned __int64 ptrFromStack = *(unsigned __int64*)(ExceptionInfo->ContextRecord->Rsp + 0x30);
            char msg[256];
            unsigned long written;
            sprintf_s(msg, "[VEH] Stack Pointer + 0x30 = 0x%llX\n", ptrFromStack);
            WriteFile(g_bpInfo.hPipe, msg, strlen(msg), &written, 0);

            // Restore original byte
            unsigned long oldProt;
            VirtualProtect(g_bpInfo.address, 1, PAGE_EXECUTE_READWRITE, &oldProt);
            *g_bpInfo.address = g_bpInfo.originalByte;
            VirtualProtect(g_bpInfo.address, 1, oldProt, &oldProt);

            ExceptionInfo->ContextRecord->Rip += 1;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

void SetBreakpoint(void* pipe, BYTE* addr)
{
    DWORD oldProt;
    VirtualProtect(addr, 1, PAGE_EXECUTE_READWRITE, &oldProt);

    g_bpInfo.hPipe = pipe;
    g_bpInfo.address = addr;
    g_bpInfo.originalByte = *addr;

    *addr = 0xCC; // INT3
    VirtualProtect(addr, 1, oldProt, &oldProt);

    AddVectoredExceptionHandler(1, MyVehHandler);
}

void SendHeartbeats() // main thread for dll
{
    void* hPipe = nullptr;
    while (hPipe == nullptr)
    {
        hPipe = CreateFileA(
            "\\\\.\\pipe\\AgentPipe",
            GENERIC_WRITE,
            0, NULL,
            OPEN_EXISTING,
            0, NULL);
        if (hPipe == nullptr) Sleep(500);
    }
    
    const char* msg = "Pipe Connected!\n";
    unsigned long writt;
    WriteFile(hPipe, msg, strlen(msg), &writt, NULL);

    // stuff
    void* modBase = GetModuleHandle(NULL);
    char* addr = (char*)modBase + 0x11FA; // NOP

    unsigned long pid = GetCurrentProcessId();
    
    std::vector<unsigned long> threads = ThreadID(pid);
    // stuff

    while (1) 
    {
        while (hPipe == nullptr)
        {
            hPipe = CreateFileA(
                "\\\\.\\pipe\\AgentPipe",
                GENERIC_WRITE,
                0, NULL,
                OPEN_EXISTING,
                0, NULL);
            if (hPipe == nullptr) Sleep(500);
        }

        if (GetAsyncKeyState(VK_F2) & 1)
        {
            char message[100] = {};
            unsigned long writ;
            sprintf_s(message, "Module Base -> 0x%llX\n", modBase);
            WriteFile(hPipe, message, strlen(message), &writ, NULL);
        }

        if (GetAsyncKeyState(VK_F3) & 1)
        {
            char message[256] = {};
            unsigned long writ;
            int len = sprintf_s(message, sizeof(message), "Bytes Read -> ");

            for (int i = 0; i < 5; i++) // read first 6 bytes
            {
                len += sprintf_s(message + len, sizeof(message) - len, "%02X ", (unsigned char)*(addr + i));
            }

            len += sprintf_s(message + len, sizeof(message) - len, "\n");

            WriteFile(hPipe, message, len, &writ, NULL);
        }

        if (GetAsyncKeyState(VK_F4) & 1)
        {
            threads = ThreadID(pid);
            char msg[256];
            unsigned long written;
            for (int i = 0; i < threads.size(); i++)
            {
                sprintf_s(msg, "Thread ID -> %d\n", threads[i]);
                WriteFile(hPipe, msg, strlen(msg), &written, 0);
            }
        }
        if (GetAsyncKeyState(VK_F5) & 1) // works but crashes
        {
            char pattern[] = "\x90\xEB\xCC\x48\x83\xC4\x28\xC3"; // 11FA 
            char mask[] = "xxxxxxxx";
            unsigned __int64 patternscan = FindPattern((char*)modBase, 0x3000, pattern, mask);
            if (patternscan)
            {
                char msg[256];
                unsigned long written;
                sprintf_s(msg, "Pattern returned -> %llX\n", patternscan);
                WriteFile(hPipe, msg, strlen(msg), &written, 0);
                SetBreakpoint(hPipe, (BYTE*)patternscan);
            }  
        }
        Sleep(100);
    }
}

DWORD WINAPI MainThread(LPVOID) 
{
    CreateThread(0, 0, (LPTHREAD_START_ROUTINE)SendHeartbeats, 0, 0, 0);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) 
    {
        CreateThread(NULL, 0, MainThread, NULL, 0, NULL);
    }
    return TRUE;
}