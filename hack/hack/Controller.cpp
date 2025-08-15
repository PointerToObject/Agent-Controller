#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>


unsigned long GetProcID(const wchar_t* process)
{
    unsigned long pid = 0;
    void* hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 proc;
        proc.dwSize = sizeof(proc);

        if (Process32First(hSnap, &proc))
        {
            do {
                
                if (!_wcsicmp(process, proc.szExeFile))
                {
                    pid = proc.th32ProcessID;
                    break;
                }

            } while (Process32Next(hSnap, &proc));
        }
    }
    else
    {
        printf("[+] Failed to create handle!\n");
    }

    CloseHandle(hSnap);
    return pid;
}

void inject(unsigned long pid)
{
    const char* dllPath = "C:\\Users\\aiden\\source\\repos\\hack\\x64\\Release\\agentdll.dll"; size_t lol = strlen(dllPath) + 1;

    void* hProc = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);

    void* alloc = VirtualAllocEx(hProc, 0, lol, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    WriteProcessMemory(hProc, alloc, dllPath, lol, 0);

    void* hThread = CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, alloc, 0, 0);
}

int main() 
{
    // Get PID
    unsigned long pid = GetProcID(L"Process.exe");

    while(!pid)
    {
        printf("[+] Please Open Process!\n");
        Sleep(250);
        pid = GetProcID(L"Process.exe");
        system("CLS");
    }
    printf("[Controller] Process ID -> %d\n", pid);


    // create pipe

    printf("[Controller] Creating Pipe \n");

    void* hPipe = CreateNamedPipeA(
        "\\\\.\\pipe\\AgentPipe",
        PIPE_ACCESS_INBOUND,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1, 0, 0, 0, NULL);

    if (hPipe == INVALID_HANDLE_VALUE) {
        printf("Failed to create pipe\n");
        return 1;
    }

    printf("[Controller] Waiting for agent to connect \n");

    // dll injection
    inject(pid);
    printf("[Controller] Dll injected\n");
    // accept connection 
    if (!ConnectNamedPipe(hPipe, NULL)) 
    {
        printf("Failed to connect pipe\n");
        CloseHandle(hPipe);
        return 1;
    }

    char buffer[128];
    unsigned long bytesRead;

    while (1) 
    {
        int success = ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL);
        buffer[bytesRead] = '\0';
        printf("[Agent] %s", buffer);

        if (!success) 
        {
            unsigned long err = GetLastError();
            if (err == ERROR_BROKEN_PIPE) 
            {
                printf("Agent disconnected.\n");
                break;
            }
            Sleep(100);
            continue;
        }
    }
  

    return 0;
}
