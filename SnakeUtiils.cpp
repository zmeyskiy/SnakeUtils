#include <iostream>
#include <windows.h>
#include <fstream>
#include <regex>
#include <string>

void MonitorFileChanges(LPCWSTR directory) 
{
    HANDLE hDir = CreateFile(directory, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, NULL);
    if (hDir == INVALID_HANDLE_VALUE) {
        std::cout << " [Error] Failed to open directory: " << directory << std::endl;
        return;
    }
    char buffer[8192];
    DWORD bytesReturned;
    OVERLAPPED overlapped;
    memset(&overlapped, 0, sizeof(overlapped));
    overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    while (true) {
        bool waitResult = ReadDirectoryChangesW(hDir, &buffer, sizeof(buffer), TRUE,
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE, &bytesReturned,
            &overlapped, NULL);

        if (!waitResult) {
            std::cout << " [Error] Failed to monitor changes in directory: " << directory << std::endl;
            break;
        }

        DWORD wait = WaitForSingleObject(overlapped.hEvent, INFINITE);
        if (wait == WAIT_FAILED) {
            std::cout << " [Error] Failed to wait for directory changes: " << directory << std::endl;
            break;
        }

        FILE_NOTIFY_INFORMATION* notifyInfo = (FILE_NOTIFY_INFORMATION*)&buffer;
        while (true) {
            std::wstring fileName(notifyInfo->FileName, notifyInfo->FileNameLength / 2);
            std::wcout << " Detected new files: " << fileName << std::endl;

            if (notifyInfo->NextEntryOffset == 0)
                break;

            notifyInfo = (FILE_NOTIFY_INFORMATION*)((char*)notifyInfo + notifyInfo->NextEntryOffset);
        }

        ResetEvent(overlapped.hEvent);
    }

    CloseHandle(hDir);
    CloseHandle(overlapped.hEvent);
}
void inject(DWORD id, const char* pathToDLL)
{
    const char* dllPath = pathToDLL;

    DWORD processId = id;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (hProcess == NULL)
    {
        std::cerr << " [Error] Opening process error\n" << std::endl;
        return;
    }

    LPVOID loadLibraryAddr = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");

    LPVOID remoteDllPath = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remoteDllPath == NULL)
    {
        std::cerr << " [Error] Memory allocating error\n" << std::endl;
        CloseHandle(hProcess);
        return;
    }

    if (!WriteProcessMemory(hProcess, remoteDllPath, dllPath, strlen(dllPath) + 1, NULL))
    {
        std::cerr << " [Error] Write DLL path to memory error\n" << std::endl;
        VirtualFreeEx(hProcess, remoteDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE) loadLibraryAddr, remoteDllPath, 0, NULL);
    if (hThread == NULL)
    {
        std::cerr << " [Error] Creating thread in process error\n" << std::endl;
        VirtualFreeEx(hProcess, remoteDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }

    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteDllPath, 0, MEM_RELEASE);
    CloseHandle(hProcess);
}

int main() 
{
    const char* title = ("SnakeUtils");
    SetConsoleTitleA(title);
    std::cout << "\n Change action:\n\n";
    std::cout << " [1] Detect new files in your PC\n [2] Inject DLL to process\n\n";
admin:
    std::cout << " admin@snake: ";
    std::string getDLLpath;
    int id;
    int option;
    std::cin >> option;
    switch (option)
    {
    case 1:
        MonitorFileChanges(L"C:\\");
    case 2:
        char dllPath[MAX_PATH];
        std::cout << "\n Please, enter process ID: ";
        std::cin >> id;
        std::cout << " Please, enter path to your DLL: ";
        std::cin >> dllPath;
        std::cout << " Please, wait...\n";
        Sleep(2000);
        inject(id, dllPath);
        goto admin;
    default:
        std::cout << " [Error] Action is not found";
        goto admin;
    }
}
