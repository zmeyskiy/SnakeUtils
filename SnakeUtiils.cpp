#include <iostream>
#include <windows.h>
#include <fstream>
#include <regex>
#include <string>
#include <TlHelp32.h>

#pragma comment(lib, "ws2_32.lib")

void httpdebugger(int port)
{
    WSADATA wsaData;
    SOCKET listeningSocket, clientSocket;
    struct sockaddr_in serverAddress, clientAddress;
    int clientAddressSize, bytesReceived;
    char buffer[4096];

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << " [Error] Failed to initialize Winsock" << std::endl;
        return;
    }

    listeningSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (listeningSocket == INVALID_SOCKET) {
        std::cerr << " [Error] Failed to create listening socket" << std::endl;
        return;
    }

    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = INADDR_ANY;
    serverAddress.sin_port = htons(port);

    if (bind(listeningSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) == SOCKET_ERROR) {
        std::cerr << " [Error] Failed to bind listening socket" << std::endl;
        return;
    }

    if (listen(listeningSocket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << " [Error] Failed to start listening" << std::endl;
        return;
    }

    std::cout << " Listening for incoming connections..." << std::endl;

    while (true) {
        clientAddressSize = sizeof(clientAddress);
        clientSocket = accept(listeningSocket, (struct sockaddr*)&clientAddress, &clientAddressSize);
        if (clientSocket == INVALID_SOCKET) {
            std::cerr << " [Error] Failed to accept client connection" << std::endl;
            continue;
        }

        memset(buffer, 0, sizeof(buffer));
        bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
        if (bytesReceived > 0) {
            std::cout << " Received request:" << std::endl;
            std::cout << " " << buffer << std::endl;
        }

        const char* response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        send(clientSocket, response, strlen(response), 0);

        closesocket(clientSocket);
    }

    closesocket(listeningSocket);

    WSACleanup();
}

void detectfiles(LPCWSTR directory) 
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

DWORD getentrypoint(HANDLE hProcess) {
    BYTE buffer[4096];
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)buffer;
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(buffer + dosHeader->e_lfanew);
    if (!ReadProcessMemory(hProcess, (LPCVOID)dosHeader, buffer, sizeof(buffer), NULL)) {
        return 0;
    }

    return ntHeaders->OptionalHeader.AddressOfEntryPoint;
}

int main() 
{
    const char* title = ("SnakeUtils");
    SetConsoleTitleA(title);
    std::cout << "\n Change action:\n\n";
    std::cout << " [1] Detect new files in your PC\n [2] Inject DLL to process\n [3] Debug connections\n\n";
admin:
    std::cout << " admin@snake: ";
    std::string getDLLpath;
    int id;
    int option;
    std::cin >> option;
    switch (option)
    {
    case 1:
        detectfiles(L"C:\\");
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
    case 3:
        int portyanka;
        std::cout << "\n Please, enter port: ";
        std::cin >> portyanka;
        httpdebugger(portyanka);
    default:
        std::cout << " [Error] Action is not found\n";
        goto admin;
    }
}
