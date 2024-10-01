/*
Copyright 2020 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <inttypes.h>

// shared memory stuff

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32)
#include <windows.h>
#else
#include <sys/mman.h>
#endif
#include <string>

#define MAX_SAMPLE_SIZE 1000000
#define SHM_SIZE (4 + MAX_SAMPLE_SIZE)
unsigned char *shm_data;

bool use_shared_memory;

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32)

int setup_shmem(const char* name) {
  HANDLE map_file;

  map_file = OpenFileMapping(
    FILE_MAP_ALL_ACCESS,   // read/write access
    FALSE,                 // do not inherit the name
    name);            // name of mapping object

  if (map_file == NULL) {
    printf("Error accessing shared memory\n");
    return 0;
  }

  shm_data = (unsigned char*)MapViewOfFile(map_file, // handle to map object
    FILE_MAP_ALL_ACCESS,  // read/write permission
    0,
    0,
    SHM_SIZE);

  if (shm_data == NULL) {
    printf("Error accessing shared memory\n");
    return 0;
  }

  return 1;
}

#else

int setup_shmem(const char *name)
{
#ifdef __ANDROID__
  printf("Shared memory not supported on Android\n");
  return 0;
#else
  int fd;

  // get shared memory file descriptor (NOT a file)
  fd = shm_open(name, O_RDONLY, S_IRUSR | S_IWUSR);
  if (fd == -1)
  {
    printf("Error in shm_open\n");
    return 0;
  }

  // map shared memory to process address space
  shm_data = (unsigned char *)mmap(NULL, SHM_SIZE, PROT_READ, MAP_SHARED, fd, 0);
  if (shm_data == MAP_FAILED)
  {
    printf("Error in mmap\n");
    return 0;
  }

  return 1;
#endif
}

#endif

// used to force a crash
char *crash = NULL;

// ensure we can find the target

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32)
#define FUZZ_TARGET_MODIFIERS __declspec(dllexport)
#else
#define FUZZ_TARGET_MODIFIERS __attribute__ ((noinline))
#endif



#include <fstream>
#include <ctime>
#include <iomanip>
#include <sstream>
void writeLog(const char* format, ...) {
    std::time_t now = std::time(nullptr);
    std::tm* now_tm = std::localtime(&now);

    // logfilename = date
    std::string logFileName = "C:\\Users\\Administrator\\Documents\\GitHub\\Jackalope\\build\\Release\\out\\test.log";

    // open or create, ios::app append
    std::ofstream logFile(logFileName, std::ios::app);

    if (!logFile.is_open()) {
        printf("Unable to open log file : %s", logFileName.c_str());
        return;
    }

    // va_list: changable params
    va_list args;
    va_start(args, format);
    // a big buffer for format string
    const int bufferSize = 1024;
    char buffer[bufferSize];
    int length = std::vsnprintf(buffer, bufferSize, format, args);
    if (length < 0 || length >= bufferSize) {
        printf("Formatted log message is too long or an error occurred\n");
        va_end(args);
        return;
    }
    std::stringstream ss;
    ss.write(buffer, length);

    // write file
    logFile << "[" << std::put_time(now_tm, "%Y-%m-%d %H:%M:%S") << "] " << ss.str() << std::endl;

    logFile.close();
}



// parse the quotes
//std::string escapeQuotes(const std::string& input) {
//    std::string output;
//    for (char ch : input) {
//        if (ch == '"') {
//            output += '\\';
//        }
//        output += ch;
//    }
//    return output;
//}

#include <sstream>
#include <string>
#include <vector>
// execute and return output
int executeCommand(const std::string& command) {
    SECURITY_ATTRIBUTES saAttr;
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    HANDLE hChildStdoutRd, hChildStdoutWr, hChildStderrRd, hChildStderrWr;

    //if (!CreatePipe(&hChildStdoutRd, &hChildStdoutWr, &saAttr, 0)) {
    //    //throw std::runtime_error("StdoutRd CreatePipe");
    //    writeLog("Exception: StdoutRd CreatePipe");
    //    return -1;
    //}
    //if (!CreatePipe(&hChildStderrRd, &hChildStderrWr, &saAttr, 0)) {
    //    //throw std::runtime_error("StderrRd CreatePipe");
    //    writeLog("Exception: StderrRd CreatePipe");
    //    return -1;
    //}

    //// make sure the handles are closed.
    //SetHandleInformation(hChildStdoutRd, HANDLE_FLAG_INHERIT, 0);
    //SetHandleInformation(hChildStderrRd, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA siStartInfo;
    PROCESS_INFORMATION piProcInfo;
    ZeroMemory(&siStartInfo, sizeof(STARTUPINFOA));
    siStartInfo.cb = sizeof(STARTUPINFOA);
   /* siStartInfo.hStdError = hChildStderrWr;
    siStartInfo.hStdOutput = hChildStdoutWr;
    siStartInfo.dwFlags |= STARTF_USESTDHANDLES;*/

    // son proc
    if (!CreateProcessA(NULL, (LPSTR)command.c_str(), NULL, NULL, TRUE, 0, NULL, NULL, &siStartInfo, &piProcInfo)) {
        writeLog("Exception: CreateProcess");
        return -1;
    }

    //CloseHandle(hChildStdoutWr);
    //CloseHandle(hChildStderrWr);

    //std::vector<char> buffer(1024, 0);
    //std::stringstream output;
    //// read output
    //while (true) {
    //    DWORD bytesRead = 0;
    //    if (!ReadFile(hChildStdoutRd, buffer.data(), buffer.size(), &bytesRead, NULL) || bytesRead == 0) {
    //        break;
    //    }
    //    output.write(buffer.data(), bytesRead);
    //}

    //// read std error
    //while (true) {
    //    DWORD bytesRead = 0;
    //    if (!ReadFile(hChildStderrRd, buffer.data(), buffer.size(), &bytesRead, NULL) || bytesRead == 0) {
    //        break;
    //    }
    //    output.write(buffer.data(), bytesRead);
    //}

    // wait for son proc
    WaitForSingleObject(piProcInfo.hProcess, INFINITE);

    CloseHandle(hChildStdoutRd);
    CloseHandle(hChildStderrRd);
    CloseHandle(piProcInfo.hProcess);
    CloseHandle(piProcInfo.hThread);


    //if (output.str().find("Exception")) {
    //    writeLog(output.str().c_str());
    //    return -1;
    //}
    //else {
    //    return 0;
    //}
    return 0;
}


#include <filesystem>
bool CopyFileAndAddPS1Extension(const char* sourcePath) {
    std::filesystem::path sourceFilePath(sourcePath);

    //std::string fileName = sourceFilePath.filename().string(); // filename
    std::string directoryName = sourceFilePath.parent_path().string(); // path of parent
    //std::string fileName = sourceFilePath.stem().string(); // name without extension
    std::string newFilePath = directoryName + "\\tmpsample.ps1";
    printf(newFilePath.c_str());
    HANDLE hSourceFile = CreateFileA(sourcePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hSourceFile == INVALID_HANDLE_VALUE) {
        printf("Failed to open source file: %s\n", sourcePath);
        return false;
    }

    HANDLE hDestFile = CreateFileA(newFilePath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDestFile == INVALID_HANDLE_VALUE) {
        printf("Failed to create destination file: %s", newFilePath.c_str());
        CloseHandle(hSourceFile);
        return false;
    }

    // copy file
    DWORD bytesRead;
    const DWORD bufferSize = 4096;
    char buffer[bufferSize];

    while (ReadFile(hSourceFile, buffer, bufferSize, &bytesRead, NULL) && bytesRead > 0) {
        DWORD bytesWritten;
        if (!WriteFile(hDestFile, buffer, bytesRead, &bytesWritten, NULL)) {
            printf("Failed to write to destination file: %s", newFilePath.c_str());
            CloseHandle(hSourceFile);
            CloseHandle(hDestFile);
            return false;
        }
    }

    CloseHandle(hSourceFile);
    CloseHandle(hDestFile);

    // run the powershell script
    //ShellExecuteA(NULL, "open", "powershell.exe", ("-File \"" + newFilePath + "\"").c_str(), NULL, SW_HIDE);
    int cpresult = executeCommand("echo A | powershell.exe -File \"" + newFilePath + "\"");

    return cpresult == 0;
}


// actual target function

int FUZZ_TARGET_MODIFIERS fuzz(char *name) {
  char *sample_bytes = NULL;
  uint32_t sample_size = 0;
  
  // read the sample either from file or
  // shared memory
  if (use_shared_memory) {
      sample_size = *(uint32_t*)(shm_data);
      if (sample_size > MAX_SAMPLE_SIZE) sample_size = MAX_SAMPLE_SIZE;
      sample_bytes = (char*)malloc(sample_size);
      if (sample_bytes != 0) {
          memcpy(sample_bytes, shm_data + sizeof(uint32_t), sample_size);
      }
      else {
          printf("malloc failed in fuzz(char* name) - if(use_shared_memory)\n");
      }
  }
  else {
      printf(name);
      if (!CopyFileAndAddPS1Extension(name)) {
          return -1; // false
      }

    //FILE *fp = fopen(name, "rb");
    //if(!fp) {
    //  writeLog("Error opening %s\n", name);
    //  return -1;
    //}
    //fseek(fp, 0, SEEK_END);
    //sample_size = ftell(fp);
    //fseek(fp, 0, SEEK_SET);

    //sample_bytes = (char *)malloc(sample_size);
    //
    //fread(sample_bytes, 1, sample_size, fp);
    //sample_bytes[sample_size] = '\0';

    //char line[213];
    //while (fgets(line, sizeof(line), fp)) {
    //    // remove \n
    //    //line[strcspn(line, "\n")] = '\0';
    //    size_t len = strlen(line);
    //    if (len > 0 && line[len - 1] == '\n') {
    //        line[len - 1] = '\0';
    //    }

    //    // parse "
    //    std::string escapedLine = escapeQuotes(line);
    //    // construct command
    //    std::string command = "powershell -Command \"" + escapedLine + "\"";
    //    writeLog("Command: %s\n", command.c_str());

    //    // execute
    //    int status = executeCommand(command);
    //    // output the result
    //    if (status == -1) {
    //        writeLog("Failed to execute command\n");
    //        return status;
    //    }
    //    else {
    //        writeLog("Command executed with exit status: %d\n", status);
    //        return 0;
    //    }
    //}

    //fclose(fp);
  }

  //std::string command = sample_bytes;
  //command = "powershell -Command \"" + command + "\"";
  //printf("Command: %s\n", command.c_str());
  //// execute the command
  //int status = system(command.c_str());

  //// output
  //if (status == -1) {
  //    printf("Failed to execute command\n");
  //}
  //else {
  //    printf("Command executed with exit status: %d\n", status);
  //}

  //if(sample_size >= 4) {
  //  // check if the sample spells "test"
  //  if(*(uint32_t *)(sample_bytes) == 0x74736574) {
  //    // if so, crash
  //    crash[0] = 1;
  //  }
  //}
  
  if(sample_bytes) free(sample_bytes);
  return 0; // TODO shared memory version
}

int main(int argc, char **argv)
{
  if(argc != 3) {
    printf("Usage: %s <-f|-m> <file or shared memory name>\n", argv[0]);
    return 0;
  }
  
  if(!strcmp(argv[1], "-m")) {
    use_shared_memory = true;
  } else if(!strcmp(argv[1], "-f")) {
    use_shared_memory = false;
  } else {
    printf("Usage: %s <-f|-m> <file or shared memory name>\n", argv[0]);
    return 0;
  }

  // map shared memory here as we don't want to do it
  // for every operation
  if(use_shared_memory) {
    if(!setup_shmem(argv[2])) {
      printf("Error mapping shared memory\n");
    }
  }

  fuzz(argv[2]);
  
  return 0;
}
