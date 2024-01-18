#include <stdexcept>
#include <regex>

#define SPDLOG_WCHAR_TO_UTF8_SUPPORT
#include <spdlog/spdlog.h>
#include <wil/resource.h>

#include <Windows.h>
#include <tlhelp32.h>
#include <psapi.h>

using namespace std::chrono_literals;

std::once_flag adjust_priv_once;

int find_process_pid(std::wstring process_name) {
    auto snapshot = wil::unique_handle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0));
    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(entry);
    if (!Process32FirstW(snapshot.get(), &entry)) return {};
    while (Process32NextW(snapshot.get(), &entry)) {
        if (_wcsicmp(entry.szExeFile, process_name.c_str()) == 0) {
            return entry.th32ProcessID;
        }
    }
    return 0;
}

int patch() {
    std::call_once(adjust_priv_once, [] {
        wil::unique_handle token;
        if (!OpenProcessToken(GetCurrentProcess(), 32, token.addressof())) {
            spdlog::critical("OpenProcessToken failed, LastError = {}", GetLastError());
            return 1;
        }
        TOKEN_PRIVILEGES token_priv{};
        if (!LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &token_priv.Privileges[0].Luid)) {
            spdlog::critical("LookupPrivilegeValueW failed, LastError = {}", GetLastError());
            return 1;
        }
        token_priv.PrivilegeCount = 1;
        token_priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (!AdjustTokenPrivileges(token.get(), FALSE, &token_priv, 0, nullptr, nullptr)) {
            spdlog::critical("AdjustTokenPrivileges failed, LastError = {}", GetLastError());
            return 1;
        }
        spdlog::info("SeDebugPrivilege enabled", GetLastError());
    });

    auto const PROCESS_NAME = L"ffxiv_dx11.exe";
    auto pid = find_process_pid(PROCESS_NAME);
    if (!pid) {
        spdlog::warn(L"The game '{}' is not running, I am still waiting...", PROCESS_NAME);
        do {
            std::this_thread::sleep_for(1s);
            pid = find_process_pid(PROCESS_NAME);
        } while (!pid);
    }
    spdlog::info("Found the game，PID = {}", pid);

    auto process = wil::unique_handle(OpenProcess(0x1F0FFF, FALSE, pid));
    if (!process) {
        spdlog::critical("OpenProcess failed, LastError = {}", GetLastError());
        return 1;
    }
    for (int retry = 0; retry < 3; retry++, std::this_thread::sleep_for(1s)) {
        HMODULE module_handle;
        DWORD module_handle_count = 0;
        if (!EnumProcessModulesEx(process.get(), &module_handle, sizeof(module_handle), &module_handle_count, LIST_MODULES_64BIT)) {
            spdlog::critical("EnumProcessModulesEx failed, LastError = {}", GetLastError());
            return 1;
        }
        MODULEINFO module_info{};
        if (!GetModuleInformation(process.get(), module_handle, &module_info, sizeof(module_info))) {
            spdlog::critical("GetModuleInformation failed, LastError = {}", GetLastError());
            return 1;
        }
        std::string module_data(module_info.SizeOfImage, '\0');
        if (!ReadProcessMemory(process.get(), module_info.lpBaseOfDll, module_data.data(), module_data.size(), nullptr)) {
            spdlog::critical("ReadProcessMemory failed, LastError = {}", GetLastError());
            return 1;
        }

        /*
                           74_04_32 DB EB 42 48 8B 01 8B D7
            FF 90 E0 09 00 00 84 C0 75 33 48 8B 0D 57 83 90
            01 BA CE 00 00 00 48 83 C1 10 E8 41 84 84 FF 83
            78 20 00 74 18 8B D7 48 8D 0D F2 E3 95 01 E8 CD
            E1 15 00 33 C9 0F B6 DB 3C 01 0F 44 D9 0F B6 D3
            48 8D 4C 24 20 E8 36 3D C9 FF 48 8D 4C 24 20 E8
            1C 13 C9 FF 48 8B 5C 24 60 B8 01 00 00 00 48 83
            C4 50 5F C3
        */

        spdlog::info("Finding the target pattern in RAM...");
        auto re = std::regex(R"(\x74(.)\x32\xdb\xeb\x42\x48\x8b\x01\x8b)");
        auto begin = std::sregex_iterator(module_data.begin(), module_data.end(), re);
        if (begin == std::sregex_iterator()) {
            spdlog::warn("Cannot find the target pattern, retrying...");
            continue;
        }
        spdlog::info("Writing the patch...");
        char patch_byte = '\x2e'; // Jump further
        if (!WriteProcessMemory(process.get(), static_cast<char *>(module_info.lpBaseOfDll) + begin->position(1), &patch_byte, 1, nullptr)) {
            spdlog::critical("WriteProcessMemory failed, LastError = {}", GetLastError());
            return 1;
        }
        spdlog::info("SUCCESS! The patch applied!");
        spdlog::info("Waiting for the game to exit...");
        while (find_process_pid(PROCESS_NAME)) {
            std::this_thread::sleep_for(1s);
        }
        spdlog::info("The game exited.");
        return 0;
    }
    spdlog::error("FAILED! Too many retries.");
    return 1;
}

int main() {
    int ret;
    do {
        ret = patch();
    } while (ret == 0);
    spdlog::info("Will exit 3s later...");
    std::this_thread::sleep_for(3s);
    return ret;
}
