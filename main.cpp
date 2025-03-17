#include <fmt/core.h>
#include <iostream>
#include <vector>
#include <fstream>
#include <libloaderapi.h>
#include <filesystem>
#include <windows.h>
#include <libhat/Scanner.hpp>
#include <map>
#include <tuple>

class StringUtils {
public:
    static std::string wstringToString(const std::wstring& wstr) {
        int size_needed = WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
        std::string str(size_needed, 0);
        WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), -1, &str[0], size_needed, nullptr, nullptr);
        return str;
    }
};

class FileUtils {
public:
    static IMAGE_NT_HEADERS& getNTHeaders(const hat::process::module mod) {
        auto* scanBytes = reinterpret_cast<std::byte*>(mod.address());
        auto* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(mod.address());
        return *reinterpret_cast<IMAGE_NT_HEADERS*>(scanBytes + dosHeader->e_lfanew);
    }

    static std::string getFileVersion(const std::filesystem::path& filePath) {
        std::wstring filePathWStr = filePath.wstring();
        LPCWSTR filePathWCStr = filePathWStr.c_str();

        DWORD handle = 0;
        DWORD size = GetFileVersionInfoSizeW(filePathWCStr, &handle);
        if (size == 0) {
            return "Unknown Version";
        }

        std::vector<char> data(size);
        if (!GetFileVersionInfoW(filePathWCStr, handle, size, data.data())) {
            return "Unknown Version";
        }

        void* versionInfo = nullptr;
        UINT len = 0;
        if (VerQueryValueW(data.data(), L"\\StringFileInfo\\040904b0\\ProductVersion", &versionInfo, &len)) {
            return StringUtils::wstringToString(std::wstring(reinterpret_cast<wchar_t*>(versionInfo), len));
        }

        return "Unknown Version";
    }
};

class Function {
    uintptr_t startAddress;
    uintptr_t endAddress;
    std::vector<Function&> xrefs;
    std::vector<Function&> calls;
    std::vector<std::string_view> strings; // null-terminated

    explicit Function(uintptr_t startAddress, uintptr_t endAddress) : startAddress(startAddress), endAddress(endAddress) {};

    [[nodiscard]] uintptr_t getStartAddress() const {
        return startAddress;
    }

    [[nodiscard]] uintptr_t getEndAddress() const {
        return endAddress;
    }

    [[nodiscard]] bool belongsToFunction(uintptr_t address) const {
        return startAddress <= address <= endAddress;
    }

    void addCall(Function& function) {
        calls.emplace_back(function);
    }

    void addXREF(Function& function) {
        xrefs.emplace_back(function);
    }
};

class Minecraft {
    std::vector<std::byte> data;
    std::map<uintptr_t, Function> functions;
    std::string version;
    std::filesystem::path path;
public:
    explicit Minecraft(const std::filesystem::path& executablePath) {
        path = executablePath;
        version = FileUtils::getFileVersion(executablePath);
    }

    void loadData() {
        loadData(path);
    }

    std::string getVersion() {
        return version;
    }

    uintptr_t getOffset(const uintptr_t address) {
        return address - reinterpret_cast<uintptr_t>(data.data());
    }



    int getCount(const hat::signature_view& signature) {
        // 48 8D 05 ? ? ? ? vtables, vtable functions inside
        // E9 ? ? ? ? | E8 ? ? ? ? functions, before func start CC byte
        const auto module = hat::process::module_at(data.data());
        const auto textData = module.value().get_section_data(".text");
        std::vector<hat::scan_result> result = find_all_pattern(textData.begin(), textData.end(), signature, hat::scan_alignment::X1, hat::scan_hint::x86_64);

        return (int)result.size();
    }

    uintptr_t findSig(const hat::signature_view& signature) {
        const auto module = hat::process::module_at(data.data());
        const auto result = find_pattern(signature, ".text", module.value(), hat::scan_alignment::X1, hat::scan_hint::x86_64);

        if (result.has_result()) {
            return getOffset(reinterpret_cast<uintptr_t>(result.get()));
        }
        return 0;
    }

    int getCount(std::string_view signature) {
        const auto parsed = hat::parse_signature(signature);
        return getCount(parsed.value());
    }

    uintptr_t findSig(std::string_view signature) {
        const auto parsed = hat::parse_signature(signature);
        return findSig(parsed.value());
    }

    void loadData(const std::filesystem::path& executablePath) {
        if (!data.empty())
            return;

        std::ifstream file(executablePath, std::ios::binary);
        if (!file.is_open()) {
            fmt::print("Failed to open file: {}\n", executablePath.string());
            return;
        }

        file.seekg(0, std::ios::end);
        std::streampos fileSize = file.tellg();
        file.seekg(0, std::ios::beg);

        std::vector<std::byte> buffer(fileSize);

        file.read(reinterpret_cast<char*>(buffer.data()), fileSize);
        file.close();

        auto virtual_module = hat::process::module_at(buffer.data()).value();
        auto& ntHeaders = FileUtils::getNTHeaders(virtual_module);

        HMODULE dll = LoadLibraryA("ntdll.dll");
        ((int(WINAPI*)(HANDLE, PVOID))GetProcAddress(dll, "NtUnmapViewOfSection"))((HANDLE)-1, (LPVOID)ntHeaders.OptionalHeader.ImageBase);

        data.resize(ntHeaders.OptionalHeader.SizeOfImage);
        ntHeaders.OptionalHeader.ImageBase = (size_t)data.data();

        memcpy(data.data(), buffer.data(), ntHeaders.OptionalHeader.SizeOfHeaders);

        const auto* sectionHeader = IMAGE_FIRST_SECTION(&ntHeaders);

        for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++)
        {
            memcpy(data.data() + sectionHeader[i].VirtualAddress,
                   buffer.data() + sectionHeader[i].PointerToRawData,
                   sectionHeader[i].SizeOfRawData);
        }
    }
};

int main() {
    std::filesystem::path basePath = "L:\\MCBedrock\\Versions";
    if (!std::filesystem::exists(basePath) || !std::filesystem::is_directory(basePath)) {
        fmt::print("Directory does not exist: {}\n", basePath.string());
        return 1;
    }


    std::map<std::string, Minecraft> mcVersions;
    std::vector<std::filesystem::path> files;

//    struct Version {
//        int major;
//        int minor;
//        int patch;
//        int build;
//    };
//
//    auto parseVersion = [](const std::string& version) -> Version {
//        std::istringstream iss(version);
//        int major = 0, minor = 0, patch = 0, build = 0;
//        char dot;
//
//        iss >> major >> dot >> minor >> dot >> patch >> dot >> build;
//        return {major, minor, patch, build};
//    };
//
//    auto getVersionKey = [](const std::tuple<int, int, int, int>& version) {
//        return std::make_tuple(std::get<0>(version), std::get<1>(version), std::get<2>(version)); // Excludes last number
//    };

    for (const auto& entry : std::filesystem::directory_iterator(basePath)) {
        auto path = entry.path() / L"Minecraft.Windows.exe";
        if (std::filesystem::exists(path)) {
            auto version = FileUtils::getFileVersion(path);

            if(mcVersions.find(version) == mcVersions.end()) {
                auto MC = Minecraft(path);
                mcVersions.try_emplace(version, MC);

                files.push_back(path);
            } else {
                continue;
            }

            fmt::print("Path: {} | Version: {}\n", path.string(), version.c_str());
        }
    }

    for (auto&& [version, mc] : mcVersions) {
        mc.loadData();
    }

    while (true) {
        std::cout << "Enter sig: ";
        std::string sig;
        std::getline(std::cin, sig);

        if (sig.empty()) continue;

        for (auto&& [version, mc] : mcVersions) { //std::cout << "Version: " << version << " | Minecraft.Windows.exe+0x" << std::hex << std::uppercase << res << std::dec << std::endl;
            auto res = mc.findSig(sig);
            auto count = mc.getCount(sig);
            if (res != 0)
                fmt::print("Version: {} | Minecraft.Windows.exe+0x{:x} | Count: {}\n", version.c_str(), res, count);

        }

        std::cout << std::flush;
    }
    return 0;
}
