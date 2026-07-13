#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <deque>
#include <algorithm>
#define NOMINMAX
#include <windows.h>
#include <winbase.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <tchar.h>
#include "SFML/Graphics.hpp"
#include "modloader.h"
#include "unzip.h"

DWORD GetProcessByName(const char* lpProcessName)
{
    PROCESSENTRY32 ProcList{};
    ProcList.dwSize = sizeof(ProcList);

    const HANDLE hProcList = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcList == INVALID_HANDLE_VALUE)
        return -1;

    if (!Process32First(hProcList, &ProcList))
        return -1;

    while (Process32Next(hProcList, &ProcList))
    {
        if (lstrcmpA(ProcList.szExeFile, lpProcessName) == 0)
            return ProcList.th32ProcessID;
    }

    return -1;
}

std::filesystem::path GetExePath()
{
    wchar_t buffer[MAX_PATH];
    DWORD len = GetModuleFileNameW(NULL, buffer, MAX_PATH);
    if (len == 0)
        throw std::runtime_error("Failed to get executable path");
    return std::filesystem::path(buffer);
}

bool IsDLL(const std::string& filePath, std::string& log)
{
    std::ifstream f(filePath, std::ios::binary);
    if (!f.is_open())
    {
        log.append("Mod could not be opened\n");
        return false;
    }

    IMAGE_DOS_HEADER dosHeader{};
    f.read(reinterpret_cast<char*>(&dosHeader), sizeof(dosHeader));
    if (!f || dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
        return false;

    f.seekg(dosHeader.e_lfanew, std::ios::beg);
    IMAGE_NT_HEADERS ntHeaders{};
    f.read(reinterpret_cast<char*>(&ntHeaders), sizeof(ntHeaders));
    if (!f || ntHeaders.Signature != IMAGE_NT_SIGNATURE)
        return false;

    f.close();
    return (ntHeaders.FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;
}

bool isZip(const std::string& filePath, std::string& log)
{
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open())
    {
        log.append("Failed to open zip\n");
        return false;
    }

    unsigned char buffer[4];
    file.read(reinterpret_cast<char*>(buffer), sizeof(buffer));
    file.close();
    return buffer[0] == 0x50 && buffer[1] == 0x4B && buffer[2] == 0x03 && buffer[3] == 0x04;
}

bool ReadFileToBuffer(const std::string& path, std::vector<uint8_t>& buffer)
{
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file)
        return false;
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    buffer.resize(size);
    return file.read(reinterpret_cast<char*>(buffer.data()), size).good();
}

DWORD RvaToOffset(DWORD rva, IMAGE_NT_HEADERS* nt, uint8_t* data)
{
    auto section = IMAGE_FIRST_SECTION(nt);

    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, section++)
    {
        DWORD start = section->VirtualAddress;
        DWORD size = section->Misc.VirtualSize;

        if (rva >= start && rva < start + size)
        {
            return section->PointerToRawData + (rva - start);
        }
    }

    return 0;
}

DWORD GetExportRVA(std::string dllPath, std::string exportName, std::string& log)
{
    std::vector<uint8_t> data;

    if (!ReadFileToBuffer(dllPath, data))
    {
        log.append("Failed to read DLL file.\n");
        return 0;
    }

    auto dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(data.data());
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        log.append("Invalid DOS signature.\n");
        return 0;
    }

    auto ntHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(data.data() + dosHeader->e_lfanew);
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        log.append("Invalid NT signature.\n");
        return 0;
    }

    auto& exportDirData = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDirData.VirtualAddress == 0)
    {
        log.append("No export table found.\n");
        return 0;
    }

    DWORD exportDirOffset = RvaToOffset(exportDirData.VirtualAddress, ntHeader, data.data());
    if (!exportDirOffset || exportDirOffset >= data.size())
    {
        log.append("Invalid export directory RVA.\n");
        return 0;
    }

    auto exportDir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(data.data() + exportDirOffset);

    DWORD namesOffset = RvaToOffset(exportDir->AddressOfNames, ntHeader, data.data());
    DWORD ordinalsOffset = RvaToOffset(exportDir->AddressOfNameOrdinals, ntHeader, data.data());
    DWORD funcsOffset = RvaToOffset(exportDir->AddressOfFunctions, ntHeader, data.data());

    if (!namesOffset || !ordinalsOffset || !funcsOffset)
    {
        log.append("Invalid export tables.\n");
        return 0;
    }

    DWORD* nameRVAs = reinterpret_cast<DWORD*>(data.data() + namesOffset);
    WORD* ordinals = reinterpret_cast<WORD*>(data.data() + ordinalsOffset);
    DWORD* funcRVAs = reinterpret_cast<DWORD*>(data.data() + funcsOffset);

    for (DWORD i = 0; i < exportDir->NumberOfNames; ++i)
    {
        DWORD nameOffset = RvaToOffset(nameRVAs[i], ntHeader, data.data());
        if (!nameOffset || nameOffset >= data.size())
            continue;

        char* name = reinterpret_cast<char*>(data.data() + nameOffset);
        if (exportName == name)
        {
            WORD ordinalIndex = ordinals[i];
            DWORD rva = funcRVAs[ordinalIndex];
            log.append("Found Ready RVA\n");
            return rva;
        }
    }

    log.append("Export not found.\n");
    return 0;
}

int Inject(const char* lpDLLName, char* lpFullDLLPath, const char* lpProcessName, std::string& log, std::string& elog)
{
    const DWORD dwProcessID = GetProcessByName(lpProcessName);

    if (dwProcessID == (DWORD)-1)
    {
        elog.append("An error occured when trying to find the target process. Is Primordialis open?\n");
        return -1;
    }

    log.append("[DLL Injector]\n");

    const DWORD dwFullPathResult = GetFullPathNameA(lpDLLName, MAX_PATH, lpFullDLLPath, nullptr);
    if (dwFullPathResult == 0)
    {
        elog.append("Attempted to load a missing mod.\n");
        return -1;
    }

    if (!IsDLL(lpFullDLLPath, elog))
    {
        elog.append("Attempted to load an invalid .DLL\n");
        return -1;
    }

    const HANDLE hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessID);
    if (hTargetProcess == INVALID_HANDLE_VALUE)
    {
        elog.append("An error occured when trying to open the target process.\n");
        return -1;
    }

    log.append("[PROCESS INJECTION]\n");
    log.append("Process opened successfully.\n");

    const LPVOID lpPathAddress = VirtualAllocEx(hTargetProcess, nullptr, lstrlenA(lpFullDLLPath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (lpPathAddress == nullptr)
    {
        elog.append("An error occured when trying to allocate memory in the target process.\n");
        return -1;
    }

    log.append("Memory allocate at 0x");
    log.append(std::to_string((UINT)(uintptr_t)lpPathAddress));
    log.append("\n");

    const DWORD dwWriteResult = WriteProcessMemory(hTargetProcess, lpPathAddress, lpFullDLLPath, lstrlenA(lpFullDLLPath) + 1, nullptr);
    if (dwWriteResult == 0)
    {
        elog.append("An error occured when trying to write the DLL path in the target process.\n");
        return -1;
    }

    log.append("DLL path writen successfully.\n");

    const HMODULE hModule = GetModuleHandleA("kernel32.dll");
    if (hModule == INVALID_HANDLE_VALUE || hModule == nullptr)
        return -1;

    const FARPROC lpFunctionAddress = GetProcAddress(hModule, "LoadLibraryA");
    if (lpFunctionAddress == nullptr)
    {
        elog.append("An error occured when trying to get \"LoadLibraryA\" address.\n");
        return -1;
    }

    log.append("LoadLibraryA address at 0x");
    log.append(std::to_string((UINT)(uintptr_t)lpFunctionAddress));
    log.append("\n");

    const HANDLE hThreadCreationResult = CreateRemoteThread(hTargetProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)lpFunctionAddress, lpPathAddress, 0, nullptr);
    if (hThreadCreationResult == INVALID_HANDLE_VALUE)
    {
        elog.append("An error occured when trying to create the thread in the target process.\n");
        return -1;
    }

    log.append("DLL Injected !\n");

    WaitForSingleObject(hThreadCreationResult, INFINITE);
    CloseHandle(hThreadCreationResult);

    std::string dllFileName = lpFullDLLPath;
    size_t pos = dllFileName.find_last_of("/\\");
    if (pos != std::string::npos)
        dllFileName = dllFileName.substr(pos + 1);

    HMODULE remoteModuleBase = nullptr;
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(hTargetProcess, hMods, sizeof(hMods), &cbNeeded))
    {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
        {
            char modName[MAX_PATH];
            if (GetModuleBaseNameA(hTargetProcess, hMods[i], modName, sizeof(modName)))
            {
                if (lstrcmpiA(modName, dllFileName.c_str()) == 0)
                {
                    remoteModuleBase = hMods[i];
                    break;
                }
            }
        }
    }

    log.append("Finding READY RVA\n");
    DWORD readyRVA = GetExportRVA(lpFullDLLPath, "READY", elog);
    if (readyRVA == 0)
    {
        log.append("Failed to find READY RVA, mod will still load. Conflicts may occur !\n");
        VirtualFreeEx(hTargetProcess, lpPathAddress, 0, MEM_RELEASE);
        CloseHandle(hTargetProcess);
        return 0;
    }
    log.append("READY RVA at 0x");
    log.append(std::to_string((UINT)readyRVA));
    log.append("\n");

    if (remoteModuleBase)
    {
        log.append("Waiting for mod to finish loading...\n");
        while (true)
        {
            bool readyFlag = false;
            SIZE_T bytesRead;
            if (ReadProcessMemory(hTargetProcess, (LPCVOID)((uintptr_t)remoteModuleBase + readyRVA), &readyFlag, sizeof(readyFlag), &bytesRead) && bytesRead == sizeof(readyFlag) && readyFlag)
                break;
            Sleep(1);
        }
        log.append("Mod loaded !\n");
    }
    else
    {
        log.append("Could not locate injected module, skipping READY wait.\n");
    }

    VirtualFreeEx(hTargetProcess, lpPathAddress, 0, MEM_RELEASE);
    CloseHandle(hTargetProcess);

    return 0;
}

std::string WrapText(const sf::Text& text, std::string& string, int max)
{
    std::string nstring("");
    sf::Text temp = text;
    temp.setString(nstring);
    for (int i = 0; i < string.length(); i++)
    {
        nstring.append(string.substr(i, 1));
        temp.setString(nstring);
        if (temp.getLocalBounds().size.x > max)
        {
            nstring.insert(nstring.length() - 1, "\n");
        }
        temp.setString(nstring);
    }
    return nstring;
}

void ModManager::Render()
{
    std::deque<std::string> trunc_log;

    int maxlines = 12;
    std::istringstream sstream(errorlog);
    std::string line;
    while (std::getline(sstream, line))
    {
        trunc_log.push_back(line);
        if (trunc_log.size() > maxlines)
            trunc_log.pop_front();
    }
    sstream = std::istringstream(log);
    sstream.seekg(0);
    while (std::getline(sstream, line))
    {
        trunc_log.push_back(line);
        if (trunc_log.size() > maxlines)
            trunc_log.pop_front();
    }

    std::string flog;
    for (int i = 0; i < trunc_log.size(); i++)
    {
        flog.append(trunc_log[i]);
        flog.append("\n");
    }

    flog = WrapText(*text, flog, 400);
    flog = "Pilus Modloader\n" + flog;
    text->setString(flog);

    text->setPosition({400, 255});
    window->clear(sf::Color::Black);

    window->draw(*text);

    sf::VertexArray bline(sf::PrimitiveType::Lines, 2);
    bline[0].position = {400, 0};
    bline[1].position = {400, 560};

    window->draw(bline);

    bline[0].position = {400, 255};
    bline[1].position = {800, 255};

    window->draw(bline);

    if (modhover != -1 && !mods.empty())
    {
        if (!m_leftPressed)
        {
            sf::RectangleShape hoverhighlight;
            hoverhighlight.setSize({399, 100});
            hoverhighlight.setPosition({0, 100 * modhover + scroll});
            hoverhighlight.setFillColor(sf::Color(20, 20, 20));

            if (hovermove)
            {
                if (hoverup)
                {
                    hoverhighlight.setSize({31, 50});
                    hoverhighlight.setPosition({400 - 32, 100 * modhover + scroll});
                }
                if (hoverdown)
                {
                    hoverhighlight.setSize({31, 50});
                    hoverhighlight.setPosition({400 - 32, 100 * modhover + scroll + 50});
                }
            }
            window->draw(hoverhighlight);
        }

        lastdescriptiontrunc = WrapText(*text, mods[modhover].description, 400);
        text->setString(lastdescriptiontrunc);
        text->setPosition({600 - text->getLocalBounds().size.x / 2, 255 / 2 - text->getLocalBounds().size.y / 2});
    }
    else
    {
        if (hoverinject)
        {
            sf::RectangleShape hoverhighlight;
            hoverhighlight.setSize({400, 254});
            hoverhighlight.setPosition({400, 0});
            hoverhighlight.setFillColor(sf::Color(20, 20, 20));

            window->draw(hoverhighlight);
        }

        text->setString("Start");
        // would add a way to check for if primordialis is already open and alternate between Start and Inject but its too slow
        text->setPosition({600 - text->getLocalBounds().size.x / 2, 255 / 2 - text->getLocalBounds().size.y / 2});
    }
    window->draw(*text);

    for (int i = 0; i < mods.size(); i++)
    {
        int mody = i * 100 + int(scroll);

        if (i % 2 == 1)
        {
            sf::RectangleShape brighterrect;
            brighterrect.setFillColor(sf::Color(255, 255, 255, 10));
            brighterrect.setSize({399, 100});
            brighterrect.setPosition({0, float(mody)});
            window->draw(brighterrect);
        }

        text->setPosition({8, float(mody + 8)});
        text->setString(mods[i].name);
        window->draw(*text);
        text->setPosition({8, float(mody + 100 - 50)});
        text->setString(mods[i].author);
        text->setFillColor(sf::Color(60, 60, 60));
        window->draw(*text);
        text->setFillColor(sf::Color::White);

        if (!mods[i].enabled)
        {
            sf::RectangleShape disablerect;
            disablerect.setSize({399, 100});
            disablerect.setPosition({0, float(mody)});
            disablerect.setFillColor(sf::Color(0, 0, 0, 150));
            window->draw(disablerect);
        }
    }

    window->display();
}

void ModManager::Update()
{
    while (const std::optional event = window->pollEvent())
    {
        if (event->is<sf::Event::Closed>())
        {
            window->close();
            SaveModOrder();
        }
        if (event->is<sf::Event::MouseButtonPressed>())
        {
            CheckSignificantMouseMovement(); // often clicking something in the modloader after not being in focus can trigger wrong button so do this

            if (event->getIf<sf::Event::MouseButtonPressed>()->button == sf::Mouse::Button::Left)
                m_leftPressed = true;

            if (modhover != -1 && !mods.empty())
            {
                if (!hovermove)
                {
                    mods[modhover].enabled = !mods[modhover].enabled;
                }
                else
                {
                    if (hoverup)
                    {
                        if (modhover > 0)
                        {
                            std::swap(mods[modhover], mods[modhover - 1]);
                        }
                    }
                    else
                    {
                        if (modhover < mods.size() - 1)
                        {
                            std::swap(mods[modhover], mods[modhover + 1]);
                        }
                    }
                    SaveModOrder();
                }
            }
            else
            {
                if (hoverinject)
                    InjectAll();
            }

            Render();
        }
        if (event->is<sf::Event::MouseButtonReleased>())
        {
            if (event->getIf<sf::Event::MouseButtonReleased>()->button == sf::Mouse::Button::Left)
                m_leftPressed = false;
        }
        if (event->is<sf::Event::KeyPressed>())
        {
            if (sf::Keyboard::isKeyPressed(sf::Keyboard::Key::I))
                InjectAll();
            if (sf::Keyboard::isKeyPressed(sf::Keyboard::Key::L))
            {
                std::ofstream file("loader_log.txt");
                file << errorlog << "\n" << log;
                file.close();
                log.clear();
                log.append("Printed log to \"loader_log.txt\"\n");
                Render();
            }
        }
        if (event->is<sf::Event::MouseMoved>())
        {
            if (CheckSignificantMouseMovement())
            {
                Render();
            }
        }
        if (event->is<sf::Event::MouseWheelScrolled>())
        {
            scroll += event->getIf<sf::Event::MouseWheelScrolled>()->delta * 20;
            scroll = std::min(0.f, scroll);
            Render();
        }
    }
}

bool ExtractModFile(std::filesystem::path moddir, unzFile& zip, std::string& elog)
{
    char filename[FILENAME_MAX];
    unz_file_info finfo;

    if (unzGetCurrentFileInfo(zip, &finfo, filename, FILENAME_MAX, nullptr, 0, nullptr, 0) != UNZ_OK)
    {
        elog.append("Failed to get file info\n");
        return false;
    }
    std::string fullPath = moddir.string();
    fullPath.append("/");
    fullPath.append(filename);

    size_t dirEnd = fullPath.find_last_of("/\\");
    std::string dirPath = fullPath.substr(0, dirEnd);

    if (!std::filesystem::exists(dirPath))
    {
        std::filesystem::create_directories(dirPath);
    }

    char* buffer = new char[finfo.uncompressed_size];
    unzReadCurrentFile(zip, buffer, finfo.uncompressed_size);

    std::ofstream f(fullPath, std::ofstream::binary);
    f.write(buffer, finfo.uncompressed_size);
    f.close();

    delete[] buffer;
    return true;
}

bool UnzipMod(std::string& zippath, std::string& elog)
{
    unzFile f = unzOpen(zippath.c_str());
    if (!f)
    {
        elog.append("Could not open mod.\n");
        unzClose(f);
        return false;
    }

    if (unzGoToFirstFile(f) != UNZ_OK)
    {
        elog.append("Mod zip is empty.\n");
        unzClose(f);
        return false;
    }

    std::filesystem::path moddir = std::filesystem::path(zippath).parent_path().append(std::filesystem::path(zippath).filename().stem().string());

    do
    {
        if (!ExtractModFile(moddir, f, elog))
        {
            elog.append("Failed to extract a file\n");
        }
    } while (unzGoToNextFile(f) == UNZ_OK);

    for (const auto& entry : std::filesystem::directory_iterator(moddir))
    {
        if (std::filesystem::is_regular_file(entry.path()))
        {
            if (lstrcmpA(entry.path().filename().extension().string().c_str(), ".dll") == 0)
            {
                zippath = entry.path().string();
                unzClose(f);
                return true;
            }
        }
    }

    elog.append("Could not find a mod dll in the extracted ZIP file\n");
    unzClose(f);
    return false;
}

bool IsProcessRunning(const char* processName) {
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    if (Process32First(snapshot, &entry)) {
        do {
            if (_tcsicmp(entry.szExeFile, processName) == 0) { // Case-insensitive comparison
                CloseHandle(snapshot);
                return true;
            }
        } while (Process32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return false;
}

void ModManager::InjectAll()
{
    log.clear();
    errorlog.clear();

    constexpr char* lpprocessname = "primordialis.exe";
    int failed = 0;

    // we assume modloader is running inside primordialis working directory

    bool ownProcess = false;
    STARTUPINFO startI{0};
    PROCESS_INFORMATION procI{0};

    if (!IsProcessRunning(lpprocessname))
    {
        char cmdLine[] = "primordialis.exe --steamless";
        ownProcess = true;
        if (!CreateProcessA(NULL, cmdLine, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &startI, &procI))
        {
            log.append("Failed to start primordialis: ");
            log.append(std::to_string(GetLastError()));
            log.append("\n");
            return;
        }
        // try get to work with suspended process in future (for main menu altering mods that might need this)
        // for now cant do that due to current method of getting the handle of mod dll when injecting
    }

    // try load plasmid api.dll first before all other mods
    if (std::filesystem::exists("mods/plasmid_api.dll"))
    {
       char dllpath[MAX_PATH];
        if (Inject("mods/plasmid_api.dll", dllpath, lpprocessname, log, log) != 0)
        {
            log.append("Failed to inject API, major issues may occur !\n");
            failed++;
        }
    }

    for (int i = 0; i < mods.size(); i++)
    {
        //skip plasmid api in modlist because should be already loaded
        if (mods[i].path.filename().string() == "plasmid_api.dll")
            continue;

        if (!mods[i].enabled)
        {
            log.append("Encountered disabled mod, skipping...\n");
            continue;
        }

        std::string injectPath = mods[i].path.string();
        char dllpath[MAX_PATH];

        if (isZip(mods[i].path.string(), log))
        {
            log.append("Unzipping mod...\n");
            std::string unzippedPath = injectPath;
            if (!UnzipMod(unzippedPath, errorlog))
            {
                log.append("[INJECTION FAILED] (");
                log.append(mods[i].path.filename().string());
                log.append(") Skipped.\n");

                Render();
                failed++;
                continue;
            }
            log.append("Mod unzipped!\n");
            injectPath = unzippedPath;
        }
        if (Inject(injectPath.c_str(), dllpath, lpprocessname, log, errorlog) != 0)
        {
            log.append("[INJECTION FAILED] (");
            log.append(mods[i].path.filename().string().c_str());
            log.append(") Skipped\n");

            Render();
            failed++;
            continue;
        }

        Render();
    }
    if (failed)
        log.append("Failed " + std::to_string(failed) + "/" + std::to_string(mods.size()) + " mods\n");
    else
        log.append("Mod injection finished successfully\n");
    Render();

    if (ownProcess)
    {
        //ResumeThread(procI.hThread);

        CloseHandle(procI.hThread);
        CloseHandle(procI.hProcess);
    }
}

void ParseModInfo(Mod* mod, std::string& log)
{
    if (isZip(mod->path.string(), log))
    {
        unzFile f = unzOpen(mod->path.string().c_str());
        if (unzGoToFirstFile(f) != UNZ_OK)
        {
            unzClose(f);
            return;
        }
        do
        {
            unz_file_info fileinfo;
            char filename[FILENAME_MAX];
            if (unzGetCurrentFileInfo(f, &fileinfo, filename, FILENAME_MAX, nullptr, 0, nullptr, 0) == UNZ_OK)
            {
                if (lstrcmpA(filename, "info.txt") == 0)
                {
                    char* data = new char[fileinfo.uncompressed_size];
                    unzOpenCurrentFile(f);
                    unzReadCurrentFile(f, data, fileinfo.uncompressed_size);

                    std::string stringdata(data, fileinfo.uncompressed_size);

                    size_t find = stringdata.find("name:");
                    if (find != std::string::npos)
                    {
                        size_t nextline = stringdata.find("\n", find);
                        if (nextline != std::string::npos)
                        {
                            mod->name = stringdata.substr(find + 5, (nextline - find - 5));
                        }
                        else
                        {
                            mod->name = stringdata.substr(find + 5, stringdata.find("\nend") - find - 5);
                        }
                    }
                    find = stringdata.find("author:");
                    if (find != std::string::npos)
                    {
                        size_t nextline = stringdata.find("\n", find);
                        if (nextline != std::string::npos)
                        {
                            mod->author = stringdata.substr(find + 7, (nextline - find - 7));
                        }
                        else
                        {
                            mod->author = stringdata.substr(find + 7, stringdata.find("\nend") - find - 7);
                        }
                    }
                    find = stringdata.find("description:");
                    if (find != std::string::npos)
                    {
                        size_t nextline = stringdata.find("\n", find);
                        if (nextline != std::string::npos)
                        {
                            mod->description = stringdata.substr(find + 12, (nextline - find - 12));
                        }
                        else
                        {
                            mod->description = stringdata.substr(find + 12, stringdata.find("\nend") - find - 12);
                        }
                    }
                    delete[] data;
                    break;
                }
            }
        } while (unzGoToNextFile(f) == UNZ_OK);
        unzClose(f);
    }
}

void ModManager::RefreshMods()
{
    log.append("Refreshing Mods...\n");
    std::vector<Mod> fmods;
    for (const auto& entry : std::filesystem::directory_iterator(modpath))
    {
        if (entry.is_regular_file())
        {
            log.append("Found Mod: ");
            log.append(entry.path().filename().stem().string());
            log.append("\n");

            Mod nmod;
            nmod.path = entry.path();
            nmod.name = entry.path().filename().stem().string();

            fmods.push_back(nmod);
        }
    }
    Render();

    for (int i = 0; i < fmods.size(); i++)
    {
        ParseModInfo(&fmods[i], log);
    }

    std::vector<Mod> finalmods;

    for (int i = 0; i < mods.size(); i++)
    {
        for (int j = 0; j < fmods.size(); j++)
        {
            if (mods[i] == fmods[j])
            {
                finalmods.push_back(fmods[j]);
                finalmods[finalmods.size() - 1].enabled = mods[i].enabled;
            }
        }
    }
    for (int i = 0; i < fmods.size(); i++)
    {
        bool addthismod = true;
        for (int j = 0; j < finalmods.size(); j++)
        {
            if (fmods[i] == finalmods[j])
            {
                addthismod = false;
                break;
            }
        }
        if (addthismod)
        {
            finalmods.push_back(fmods[i]);
        }
    }

    mods = finalmods;
    SaveModOrder();
}

void ModManager::LoadModOrder()
{
    std::ifstream file("PILUS_MODLOADER.CONFIG");

    if (!file) return;

    uint32_t num_mods;
    file.read(reinterpret_cast<char*>(&num_mods), sizeof(uint32_t));

    for (int i = 0; i < num_mods; i++)
    {
        Mod nmod;
        file.read(reinterpret_cast<char*>(&nmod.enabled), sizeof(bool));

        uint32_t pathlength = 0;
        file.read(reinterpret_cast<char*>(&pathlength), sizeof(uint32_t));
        std::string path(pathlength, '\0');
        file.read(&path[0], pathlength);
        nmod.path = std::filesystem::path(path);

        mods.push_back(nmod);
    }

    file.close();
}

void ModManager::SaveModOrder()
{
    std::ofstream file("PILUS_MODLOADER.CONFIG");

    if (!file) return;

    uint32_t num_mods = mods.size();
    file.write(reinterpret_cast<char*>(&num_mods), sizeof(uint32_t));
    for (int i = 0; i < mods.size(); i++)
    {
        file.write(reinterpret_cast<char*>(&(mods[i].enabled)), sizeof(bool));
        uint32_t pathlength = mods[i].path.string().size();
        file.write(reinterpret_cast<char*>(&pathlength), sizeof(uint32_t));
        file.write(mods[i].path.string().data(), mods[i].path.string().size());
    }

    file.close();
}

bool ModManager::CheckSignificantMouseMovement()
{
    bool change = false;
    sf::Vector2i mouse = sf::Mouse::getPosition(*window);

    if (mouse.x < 400)
    {
        if (mods.empty())
        {
            if (modhover != -1)
            {
                modhover = -1;
                change = true;
            }
        }
        else
        {
            int hoveridxnoclamp = int(mouse.y - scroll) / 100;
            int hoveridx = std::max(0, std::min(hoveridxnoclamp, (int)mods.size() - 1));
            if (modhover != hoveridx)
            {
                modhover = hoveridx;
                change = true;
            }

            if (mouse.x > 368 && hoveridxnoclamp == hoveridx)
            {
                if (!hovermove)
                {
                    hovermove = true;
                    change = true;
                }
                if (hoverup != (mouse.y - int(scroll)) % 100 < 50)
                {
                    hoverup = !hoverup;
                    change = true;
                }
                if (hoverdown == hoverup)
                {
                    hoverdown = !hoverdown;
                    change = true;
                }
            }
            else
            {
                if (hovermove)
                {
                    hovermove = false;
                    change = true;
                }
            }
        }
    }
    else
    {
        if (modhover != -1)
        {
            modhover = -1;
            change = true;
        }

        if (hoverinject != mouse.y < 255)
        {
            hoverinject = mouse.y < 255;
            change = true;
        }
    }

    return change;
}

void run()
{
    sf::RenderWindow window(sf::VideoMode({ 800, 560 }), "Pilus", sf::Style::Titlebar | sf::Style::Close);


    sf::Font font;
    sf::Text text(font);
    if (!font.openFromFile("data/CreatoDisplay-Regular.otf"))
        if (!font.openFromFile("verdana.ttf"))
            printf("FAILED TO LOAD FONT\n");

    ModManager manager;
    manager.font = &font;
    manager.text = &text;
    manager.window = &window;
    font.setSmooth(false);
    text.setCharacterSize(15);

    std::filesystem::path modpath = std::filesystem::current_path().append("mods");

    if (!std::filesystem::exists(modpath))
    {
        std::filesystem::create_directory(modpath);
        manager.log.append("Created mod directory\n");
    }

    HANDLE dirchangenotif = FindFirstChangeNotification(
        modpath.string().c_str(),
        FALSE,
        FILE_NOTIFY_CHANGE_FILE_NAME);

    manager.modpath = modpath;

    if (std::filesystem::exists("PILUS_MODLOADER.CONFIG"))
    {
        manager.LoadModOrder();
    }

    manager.RefreshMods();
    manager.Render();

    while (window.isOpen())
    {
        DWORD updatestatus = WaitForSingleObject(dirchangenotif, 0);

        switch (updatestatus)
        {
        case WAIT_OBJECT_0:
            manager.log.clear();
            manager.RefreshMods();
            FindNextChangeNotification(dirchangenotif);
            break;
        }

        manager.Update();
    }
}

#ifdef _DEBUG // cmake currently doesnt support debug build sorry ;(
int main(const int argc, char* argv[])
{
    run();
    return 0;
}
#else
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
    LPSTR lpCmdLine, int nCmdShow) {
    run();
    return 0;
}
#endif
