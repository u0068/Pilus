#include <iostream>
#include <fstream>
#include <sstream>
#include <queue>
#include <windows.h>
#include <TlHelp32.h>
#include <string>
#include "SFML/Graphics.hpp"
#include <tchar.h>
#include <filesystem>
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
        char* lpCurrentProcessName = ProcList.szExeFile;

        if (lstrcmpA(lpCurrentProcessName, lpProcessName) == 0)
            return ProcList.th32ProcessID;
    }

    return -1;
}

std::filesystem::path GetExePath()
{
    wchar_t buffer[MAX_PATH];
    DWORD len = GetModuleFileNameW(NULL, buffer, MAX_PATH);
    if (len == 0) throw std::runtime_error("Failed to get executable path");
    return std::filesystem::path(buffer);
}

bool IsDLL(const std::string& filePath, std::string& log)
{
    std::ifstream f(filePath);
    if (!f.is_open()) {
        log.append("Mod could not be opened\n");
        return false;
    }

    IMAGE_DOS_HEADER dosHeader{};
    f.read(reinterpret_cast<char*>(&dosHeader), sizeof(dosHeader));
    if (!f || dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
    {
        return false;
    }

    f.seekg(dosHeader.e_lfanew, std::ios::beg);
    IMAGE_NT_HEADERS ntHeaders{};
    f.read(reinterpret_cast<char*>(&ntHeaders), sizeof(ntHeaders));
    if (!f || ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }

    f.close();

    return (ntHeaders.FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;
}

bool isZip(const std::string& filePath, std::string& log) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        log.append("Failed to open zip\n");
        return false;
    }

    unsigned char buffer[4];
    file.read(reinterpret_cast<char*>(buffer), sizeof(buffer));

    file.close();
    return buffer[0] == 0x50 && buffer[1] == 0x4B && buffer[2] == 0x03 && buffer[3] == 0x04;
}


int Inject(const char* lpDLLName, const char* lpFullDLLPath, const char* lpProcessName, std::string& log, std::string& elog)
{
    const DWORD dwProcessID = GetProcessByName(lpProcessName);

    if (dwProcessID == (DWORD)-1)
    {
        elog.append("An error occured when trying to find the target process. Is Primordialis open?\n");
        return -1;
    }

    log.append("[DLL Injector]\n");

    const DWORD dwFullPathResult = GetFullPathNameA(lpDLLName, MAX_PATH, const_cast<char*>(lpFullDLLPath), nullptr);
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

    const LPVOID lpPathAddress = VirtualAllocEx(hTargetProcess, nullptr, lstrlenA(lpFullDLLPath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
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

    return 0;
}

std::string WrapText(sf::Text text, std::string& string, int max)
{
    std::string nstring("");
    text.setString(nstring);
    for (int i = 0; i < string.length(); i++)
    {
        nstring.append(string.substr(i, 1));

        text.setString(nstring);
        if (text.getLocalBounds().size.x > max)
        {
            nstring.insert(nstring.length()-1, "\n");
        }
        text.setString(nstring);
    }

    return nstring;
}

void ModManager::Render()
{
    // limit log length (prioritise errorlog and last lines)

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

    text->setPosition({400 , 255});
    window->clear(sf::Color::Black);

    // draw text
    window->draw(*text);

    // draw borders
    sf::VertexArray bline(sf::PrimitiveType::Lines, 2);
    bline[0].position = {400, 0};
    bline[1].position = { 400, 560 };

    window->draw(bline);

    bline[0].position = { 400, 255 };
    bline[1].position = { 800, 255 };

    window->draw(bline);

    // draw description/inject
    if (modhover != -1 && mods.size() != 0)
    {
        if (!sf::Mouse::isButtonPressed(sf::Mouse::Button::Left)) // feedback
        {
            sf::RectangleShape hoverhighlight;
            hoverhighlight.setSize({ 399, 100 });
            hoverhighlight.setPosition({ 0, 100 * modhover + scroll });
            hoverhighlight.setFillColor(sf::Color(20, 20, 20));

            if (hovermove)
            {
                if (hoverup)
                {
                    hoverhighlight.setSize({ 31, 50 });
                    hoverhighlight.setPosition({ 400 - 32, 100 * modhover + scroll });
                }
                if (hoverdown)
                {
                    hoverhighlight.setSize({ 31, 50 });
                    hoverhighlight.setPosition({ 400 - 32, 100 * modhover + scroll + 50 });
                }
            }
            window->draw(hoverhighlight);
        }

        lastdescriptiontrunc = WrapText(*text, mods[modhover].description, 400);
        text->setString(lastdescriptiontrunc);
        text->setPosition({ 600 - text->getLocalBounds().size.x / 2, 255 / 2 - text->getLocalBounds().size.y / 2 });
    }
    else
    {
        if (hoverinject)
        {
            sf::RectangleShape hoverhighlight;
            hoverhighlight.setSize({ 400, 254 });
            hoverhighlight.setPosition({ 400, 0 });
            hoverhighlight.setFillColor(sf::Color(20, 20, 20));

            window->draw(hoverhighlight);
        }

        text->setString("Inject");
        text->setPosition({600 - text->getLocalBounds().size.x/2, 255/2 - text->getLocalBounds().size.y/2});
    }
    window->draw(*text);

    // render mods
    for (int i = 0; i < mods.size(); i++)
    {
        int mody = i * 100 + int(scroll);

        if (i % 2 == 1)
        {
            sf::RectangleShape brighterrect;
            brighterrect.setFillColor(sf::Color(255, 255, 255, 10));
            brighterrect.setSize({399, 100});
            brighterrect.setPosition({ 0, float(mody) });
            window->draw(brighterrect);
        }

        text->setPosition({ 8, float(mody + 8) });
        text->setString(mods[i].name);
        window->draw(*text);
        text->setPosition({ 8, float(mody+100-50) });
        text->setString(mods[i].author);
        text->setFillColor(sf::Color(60, 60, 60));
        window->draw(*text);
        text->setFillColor(sf::Color::White);

        if (!mods[i].enabled) // add darken effect when disabled
        {
            sf::RectangleShape disablerect;
            disablerect.setSize({ 399, 100 });
            disablerect.setPosition({ 0, float(mody) });
            disablerect.setFillColor(sf::Color(0, 0, 0, 150)); // lower opacity
            window->draw(disablerect);
        }
    }

    window->display();
    return;
}

void ModManager::Update()
{
    while (const std::optional event = window->pollEvent())
    {
        if (event->is<sf::Event::Closed>())
            window->close();
        if (event->is<sf::Event::MouseButtonPressed>())
        {
            if (modhover != -1)
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
                    else // hover down
                    {
                        if (modhover < mods.size() - 1)
                        {
                            std::swap(mods[modhover], mods[modhover + 1]);
                        }
                    }
                }
            }
            else
            {
                if (hoverinject)
                    InjectAll();
            }
            Render();
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
    char* filename[FILENAME_MAX];
    unz_file_info finfo;

    if (unzGetCurrentFileInfo(zip, &finfo, (char*)(filename), FILENAME_MAX, nullptr, 0, nullptr, 0) != UNZ_OK)
    {
        elog.append("Failed to get file info\n");
        return false;
    }
    std::string fullPath = moddir.string();
    fullPath.append("/");
    // will get directory e.g "mods/my_mod/"
    // this does make conflicts a possible issue but hopefully modmakers just don't use the same names, otherwise will need a mod folder name generation system
    fullPath.append((char*)(filename));

    size_t dirEnd = fullPath.find_last_of("/\\");

    std::string dirPath = fullPath.substr(0, dirEnd);

    if (!std::filesystem::exists(dirPath))
    {
        std::filesystem::create_directory(dirPath);
    }

    char* buffer = new char[finfo.uncompressed_size];
    unzReadCurrentFile(zip, buffer, finfo.uncompressed_size);

    std::ofstream f(fullPath, std::ofstream::binary);
    f.write(buffer, finfo.uncompressed_size);

    f.close();

    // when mods get updated all relevant files will just be overwritten, we don't need to worry about deleting old files, user should clear out mods folder whenever wanting to remove mods

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
        // we'll just continue and hopefully just have skipped some broken file that wasn't needed

    } while (unzGoToNextFile(f) == UNZ_OK);

    for (const auto& entry : std::filesystem::directory_iterator(moddir))
    {
        if (std::filesystem::is_regular_file(entry.path())) {
            if (lstrcmpA(entry.path().filename().extension().string().c_str(), ".dll") == 0)
            {
                zippath = entry.path().string();
                // set zippath to be the extracted dll, then inject that dll normally

                unzClose(f);
                return true;
            }
        }
    }

    elog.append("Could not find a mod dll in the extracted ZIP file\n");
    unzClose(f);
    return false;
}

void ModManager::InjectAll()
{
    log.clear();
    errorlog.clear();
    char* lpprocessname = "primordialis.exe";

    int failed = 0;

    for (int i = 0; i < mods.size(); i++)
    {
        std::string dllhold = mods[i].path.string();
        char dllpath[MAX_PATH];

        if (isZip(mods[i].path.string(), log))
        {
            log.append("Unzipping mod...\n");
            if (!UnzipMod(dllhold, log)) // unzip sets dllhold to be the path of the dll held in the unzipped mod, so we can use that next to actually inject
            {
                log.append("[INJECTION FAILED] (");
                log.append(mods[i].path.filename().string());
                log.append(") Skipped.\n");

                Render();
                failed++;

                continue;
            }
            log.append("Mod unzipped!\n");
        }
        if (Inject(mods[i].path.string().c_str(), dllpath, lpprocessname, log, log) != 0)
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
}

void ParseModInfo(Mod* mod, std::string& log)
{
    if (isZip(mod->path.string(), log))
    {
        // look for info.txt
        unzFile f = unzOpen(mod->path.string().c_str());


        if (unzGoToFirstFile(f) != UNZ_OK)
        {
            unzClose(f);
            return;
        }
        do
        {
            unz_file_info fileinfo;
            char* filename[FILENAME_MAX];
            if (unzGetCurrentFileInfo(f, &fileinfo, (char*)filename, FILENAME_MAX, nullptr, 0, nullptr, 0) == UNZ_OK)
            {
                if (lstrcmpA((char*)filename, "info.txt") == 0)
                {
                    char* data = new char[fileinfo.uncompressed_size];
                    unzOpenCurrentFile(f);
                    unzReadCurrentFile(f, data, fileinfo.uncompressed_size);

                    std::string stringdata(data);

                    size_t find = stringdata.find("name:");
                    if (find != std::string::npos)
                    {
                        // check if any lines after
                        size_t nextline = stringdata.find("\n", find);
                        if (nextline != std::string::npos)
                        {
                            mod->name = stringdata.substr(find + 5, (nextline - find - 5));
                        }
                        else
                        {
                            mod->name = stringdata.substr(find + 5, stringdata.find("\nend"));
                        }
                    }
                    find = stringdata.find("author:");
                    if (find != std::string::npos)
                    {
                        // check if any lines after
                        size_t nextline = stringdata.find("\n", find);
                        if (nextline != std::string::npos)
                        {
                            mod->author = stringdata.substr(find + 7, (nextline - find - 7));
                        }
                        else
                        {
                            mod->author = stringdata.substr(find + 7, stringdata.find("\nend"));
                        }
                    }
                    find = stringdata.find("description:");
                    if (find != std::string::npos)
                    {
                        // check if any lines after
                        size_t nextline = stringdata.find("\n", find);
                        if (nextline != std::string::npos)
                        {
                            mod->description = stringdata.substr(find + 12, (nextline - find - 12));
                        }
                        else
                        {
                            mod->description = stringdata.substr(find + 12, stringdata.find("\nend"));
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
    mods.clear();
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

            mods.push_back(nmod);
            // relative so we can save
        }
    }
    Render();

    // need to do seperate so we can open mod zips
    for (int i = 0; i < mods.size(); i++)
    {
        ParseModInfo(&mods[i], log);
    }
}

bool ModManager::CheckSignificantMouseMovement()
{
    bool change = false;
    sf::Vector2i mouse = sf::Mouse::getPosition(*window);

    if (mouse.x < 400) // mod list is on left half
    {
        // check for mod its hovering on
        
        // mod visual size is 100 px tall

        int hoveridxnoclamp = int(mouse.y - scroll) / 100;
        int hoveridx = std::max(0, std::min(hoveridxnoclamp, (int)mods.size() - 1));
        if (modhover != hoveridx)
        {
            modhover = hoveridx;
            change = true;
        }

        if (mouse.x > 368 && hoveridxnoclamp == hoveridx) // 32 pixels from left boundary is order config
        {
            if (!hovermove)
            {
                hovermove = true;
                change = true;
            }
            if (hoverup != (mouse.y - int(scroll)) % 100 < 50) // top 50 px in 32x100 area
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
    else
    {
        if (modhover != -1)
        {
            modhover = -1;
            change = true;
        }

        // check for inject hover

        if (hoverinject != mouse.y < 255)
        {
            hoverinject = mouse.y < 255;
            change = true;
        }
    }

    return change;
}

int main(const int argc, char* argv[])
{
    sf::RenderWindow window(sf::VideoMode({ 800, 560 }), "Pilus");

    
    sf::Font font;
    sf::Text text(font);
    if (!font.openFromFile("verdana.ttf")) // load verdana if available
        if (!font.openFromFile("data/CreatoDisplay-Regular.otf")) // try grab from primordialis instead
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
    
    manager.RefreshMods();
    manager.Render();

    while (window.isOpen())
    {
        // check for mods added/deleted to folder

        DWORD updatestatus = WaitForSingleObject(dirchangenotif, 0); // 0ms timeout so we don't interrupt update

        switch (updatestatus)
        {
        case WAIT_OBJECT_0:
            manager.log.clear();
            manager.RefreshMods();
            FindNextChangeNotification(dirchangenotif);
            break;
        }

        // update windowww

        manager.Update();
    }
}