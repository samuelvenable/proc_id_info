/*

MIT License

Copyright © 2021-2026 Samuel Venable

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

#include <proc_id_info/proc_id_info.hpp>
#if defined(__proc_id_info_supported__)
#include <algorithm>
#include <fstream>
#include <sstream>

#include <cstdlib>
#include <cstddef>
#include <cstring>
#include <climits>
#include <cstdio>

#if (!defined(_WIN32) && !defined(_WIN64))
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#endif

#if (defined(_WIN32) || defined(_WIN64))
#include <psapi.h>
#include <fileapi.h>
#include <shlwapi.h>
#include <objbase.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <processthreadsapi.h>
#elif (defined(__APPLE__) && defined(__MACH__))
#include <mach-o/dyld.h>
#include <sys/sysctl.h>
#include <libproc.h>
#elif (defined(__linux__) || defined(__ANDROID__))
#include <dirent.h>
#if __has_include(<linux/sched.h>)
// For defining PF_KTHREAD when possible...
#include <linux/sched.h>
#endif
#elif ((defined(__FreeBSD__) || defined(__FreeBSD_kernel__)) || defined(__DragonFly__) || defined(__OpenBSD__))
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <kvm.h>
#if ((defined(__FreeBSD__) || defined(__FreeBSD_kernel__)) || defined(__OpenBSD__))
#include <sys/proc.h>
#endif
#elif defined(__NetBSD__)
#include <sys/param.h>
#include <sys/sysctl.h>
#include <kvm.h>
#elif (defined(__sun) && defined(__SVR4))
#include <cerrno>
#include <kvm.h>
#include <dirent.h>
#include <libproc.h>
#include <sys/time.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/param.h>
#include <sys/procfs.h>
#endif
#include <sys/stat.h>
#if ((defined(_WIN32) || defined(_WIN64)) && defined(_MSC_VER))
#pragma comment(lib, "ntdll.lib")
#endif
#if (defined(__linux__) || defined(__ANDROID__))
#if !defined(PF_KTHREAD)
// Normally defined in <linux/sched.h> when present...
#define PF_KTHREAD 0x00200000
#endif
#endif

namespace {

  void message_pump() {
    #if (defined(_WIN32) || defined(_WIN64))
    MSG msg;
    while (PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE)) {
      TranslateMessage(&msg);
      DispatchMessage(&msg);
    }
    #endif
  }

  std::vector<std::string> string_split_by_first_equals_sign(std::string str) {
    std::size_t pos = 0;
    std::vector<std::string> vec;
    if ((pos = str.find('=')) != std::string::npos) {
      vec.push_back(str.substr(0, pos));
      vec.push_back(str.substr(pos + 1));
    }
    return vec;
  }

  #if (defined(_WIN32) || defined(_WIN64))
  enum MEMTYP {
    MEMCMD,
    MEMENV,
    MEMCWD
  };

  #if !defined(_MSC_VER)
  #pragma pack(push, 8)
  #else
  #include <pshpack8.h>
  #endif

  /* CURDIR struct from:
   https://github.com/processhacker/phnt/
   CC BY 4.0 licence */

  typedef struct {
    UNICODE_STRING DosPath;
    HANDLE Handle;
  } CURDIR;

  /* RTL_DRIVE_LETTER_CURDIR struct from:
   https://github.com/processhacker/phnt/
   CC BY 4.0 licence */

  typedef struct {
    USHORT Flags;
    USHORT Length;
    ULONG TimeStamp;
    STRING DosPath;
  } RTL_DRIVE_LETTER_CURDIR;

  /* RTL_USER_PROCESS_PARAMETERS struct from:
   https://github.com/processhacker/phnt/
   CC BY 4.0 licence */

  typedef struct {
    ULONG MaximumLength;
    ULONG Length;
    ULONG Flags;
    ULONG DebugFlags;
    HANDLE ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;
    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID Environment;
    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;
    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectories[32];
    ULONG_PTR EnvironmentSize;
    ULONG_PTR EnvironmentVersion;
    PVOID PackageDependencyData;
    ULONG ProcessGroupId;
    ULONG LoaderThreads;
    UNICODE_STRING RedirectionDllName;
    UNICODE_STRING HeapPartitionName;
    ULONG_PTR DefaultThreadpoolCpuSetMasks;
    ULONG DefaultThreadpoolCpuSetMaskCount;
  } RTL_USER_PROCESS_PARAMETERS;

  #if !defined(_MSC_VER)
  #pragma pack(pop)
  #else
  #include <poppack.h>
  #endif

  std::wstring widen(std::string str) {
    if (str.empty()) return L"";
    std::size_t wchar_count = str.size() + 1;
    std::vector<wchar_t> buf(wchar_count);
    wchar_count = (std::size_t)MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, buf.data(), (int)wchar_count);
    if (!wchar_count) return L"";
    return std::wstring { buf.data(), wchar_count };
  }

  std::string narrow(std::wstring wstr) {
    if (wstr.empty()) return "";
    int nbytes = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.length(), nullptr, 0, nullptr, nullptr);
    if (!nbytes) return "";
    std::vector<char> buf((std::size_t)nbytes);
    nbytes = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.length(), buf.data(), nbytes, nullptr, nullptr);
    if (!nbytes) return "";
    return std::string { buf.data(), (std::size_t)nbytes };
  }

  wchar_t *_wrealpath(const wchar_t *path, wchar_t *resolved_path) {
    std::wstring result;
    wchar_t buf[MAX_PATH];
    wchar_t *ptr = (((wchar_t *)resolved_path) ? ((wchar_t *)resolved_path) : ((wchar_t *)buf));
    HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (hFile != INVALID_HANDLE_VALUE) {
      unsigned long len = GetFinalPathNameByHandleW(hFile, ptr, MAX_PATH, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
      if (len && len <= MAX_PATH - 1) {
        result = ptr;
        if (!result.substr(0, 8).compare(L"\\\\?\\UNC\\")) {
          result = L"\\" + result.substr(7);
        } else if (!result.substr(0, 4).compare(L"\\\\?\\")) {
          result = result.substr(4);
        }
      }
      CloseHandle(hFile);
    }
    if (!result.empty()) {
      if (!resolved_path) {
        return _wcsdup(result.c_str());
      } else {
        wcsncpy_s(ptr, MAX_PATH, result.c_str(), _TRUNCATE);
        return (wchar_t *)ptr;
      }
    }
    return nullptr;
  }

  HANDLE open_process_with_debug_privilege(proc_id_info::proc_id_t proc_id) {
    HANDLE proc = nullptr;
    HANDLE hToken = nullptr;
    LUID luid;
    TOKEN_PRIVILEGES tkp;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
      if (LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid)) {
        tkp.PrivilegeCount = 1;
        tkp.Privileges[0].Luid = luid;
        tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (AdjustTokenPrivileges(hToken, false, &tkp, sizeof(tkp), nullptr, nullptr)) {
          proc = OpenProcess(PROCESS_ALL_ACCESS, false, proc_id);
        }
      }
      CloseHandle(hToken);
    }
    if (!proc) {
      proc = OpenProcess(PROCESS_ALL_ACCESS, false, proc_id);
    }
    return proc;
  }

  std::vector<wchar_t> cmd_env_cwd_from_proc(HANDLE proc, int type) {
    std::vector<wchar_t> buffer;
    PEB peb;
    SIZE_T nRead = 0;
    ULONG len = 0;
    PVOID buf = nullptr;
    PROCESS_BASIC_INFORMATION pbi;
    RTL_USER_PROCESS_PARAMETERS upp;
    NTSTATUS status = NtQueryInformationProcess(proc, ProcessBasicInformation, &pbi, sizeof(pbi), &len);
    ULONG error = RtlNtStatusToDosError(status);
    if (error) return buffer;
    ReadProcessMemory(proc, pbi.PebBaseAddress, &peb, sizeof(peb), &nRead);
    if (!nRead) return buffer;
    ReadProcessMemory(proc, peb.ProcessParameters, &upp, sizeof(upp), &nRead);
    if (!nRead) return buffer;
    if (type == MEMCMD) {
      buf = upp.CommandLine.Buffer;
      len = upp.CommandLine.Length;
    } else if (type == MEMENV) {
      buf = upp.Environment;
      len = (ULONG)upp.EnvironmentSize;
    } else {
      buf = upp.CurrentDirectory.DosPath.Buffer;
      len = upp.CurrentDirectory.DosPath.Length;
    }
    buffer.resize(len / 2 + 1);
    ReadProcessMemory(proc, buf, &buffer[0], len, &nRead);
    if (!nRead) return buffer;
    buffer[len / 2] = L'\0';
    return buffer;
  }
  #elif (defined(__APPLE__) && defined(__MACH__))
  enum MEMTYP {
    MEMCMD,
    MEMENV
  };

  std::vector<std::string> cmd_env_from_proc_id(proc_id_info::proc_id_t proc_id, int type) {
    std::vector<std::string> vec;
    std::size_t len = 0;
    int argmax = 0, nargs = 0;
    char *procargs = nullptr, *sp = nullptr, *cp = nullptr;
    int mib[3];
    mib[0] = CTL_KERN;
    mib[1] = KERN_ARGMAX;
    len = sizeof(argmax);
    if (sysctl(mib, 2, &argmax, &len, nullptr, 0)) {
      return vec;
    }
    procargs = (char *)malloc(argmax);
    if (!procargs) {
      return vec;
    }
    mib[0] = CTL_KERN;
    mib[1] = KERN_PROCARGS2;
    mib[2] = proc_id;
    len = argmax;
    if (sysctl(mib, 3, procargs, &len, nullptr, 0)) {
      free(procargs);
      return vec;
    }
    memcpy(&nargs, procargs, sizeof(nargs));
    cp = procargs + sizeof(nargs);
    for (; cp < &procargs[len]; cp++) {
      if (*cp == '\0') break;
    }
    if (cp == &procargs[len]) {
      free(procargs);
      return vec;
    }
    for (; cp < &procargs[len]; cp++) {
      if (*cp != '\0') break;
    }
    if (cp == &procargs[len]) {
      free(procargs);
      return vec;
    }
    sp = cp;
    int i = 0;
    while ((*sp != '\0' || i < nargs) && sp < &procargs[len]) {
      if (type && i >= nargs) {
        vec.push_back(sp);
      } else if (!type && i < nargs) {
        vec.push_back(sp);
      }
      sp += strlen(sp) + 1;
      i++;
    }
    free(procargs);
    return vec;
  }
  #elif (defined(__sun) && defined(__SVR4))
  enum MEMTYP {
    MEMCMD,
    MEMENV
  };

  std::vector<std::string> cmd_env_from_proc_id(proc_id_info::proc_id_t proc_id, int type) {
    std::vector<std::string> vec;
    auto proc_psinfo_get = [](psinfo_t *psinfo, proc_id_info::proc_id_t proc_id) {
      int fd = -1, retval = 0;
      std::string procfs_path;
      if (proc_id == proc_id_info::proc_id_from_self()) {
        procfs_path = "/proc/self/psinfo";
      } else {
        procfs_path = std::string("/proc/") + std::to_string(proc_id) + std::string("/psinfo");
      }
      if ((fd = open(procfs_path.c_str(), O_RDONLY)) == -1) {
        return ESRCH;
      }
      if (pread(fd, psinfo, sizeof(psinfo_t), 0) != sizeof(psinfo_t)) {
        retval = errno;
      }
      close(fd);
      return retval;
    };
    psinfo_t psinfo;
    char buffer[BUFSIZ];
    std::string procfs_path;
    int n = 0, err = 0, fd = -1;
    std::size_t nread = 0;
    unsigned args_size = 0;
    char **args = (char **)malloc(ARG_MAX);
    if (!args) goto finish;
    psinfo.pr_dmodel = 0;
    err = proc_psinfo_get(&psinfo, proc_id);
    if (err) {
      free(args);
      goto finish;
    }
    args_size = sizeof(*args) * ARG_MAX;
    if (proc_id == proc_id_info::proc_id_from_self()) {
      procfs_path = "/proc/self/as";
    } else {
      procfs_path = std::string("/proc/") + std::to_string(proc_id) + std::string("/as");
    }
    if ((fd = open(procfs_path.c_str(), O_RDONLY)) == -1) {
      free(args);
      goto finish;
    }
    if (args_size > sizeof(args)) {
      free(args);
      args = (char **)malloc(args_size);
      if (!args) goto finish;
    }
    if ((long)(nread = pread(fd, args, args_size, (off_t)((type != MEMCMD) ? psinfo.pr_envp : psinfo.pr_argv))) <= 0) {
      close(fd);
    }
    for (n = 0; args[n]; n++) {
      int len = 0;
      char *arg = nullptr;
      if ((long)(nread = pread(fd, buffer, sizeof(buffer), (off_t)args[n])) <= 0) {
        close(fd);
        break;
      }
      len = strlen(buffer) + 1;
      arg = (char *)malloc(len);
      if (!arg) {
        if (args) free(args);
        vec.clear();
        goto finish;
      }
      memcpy(arg, buffer, len);
      vec.push_back(arg);
    }
    if (args) {
      free(args);
    }
    finish:
    if (fd != -1) {
      close(fd);
    }
    return vec;
  }
  #endif

  #if (defined(_WIN32) || defined(_WIN64))
  bool proc_id_and_parent_proc_id_compare_creation_time(proc_id_info::proc_id_t proc_id, proc_id_info::proc_id_t parent_proc_id) {
    HANDLE proc_handle = nullptr, parent_proc_handle = nullptr;
    if ((proc_handle = open_process_with_debug_privilege(proc_id))) {
      if ((parent_proc_handle = open_process_with_debug_privilege(parent_proc_id))) {
        FILETIME proc_creation_time, proc_exit_time, proc_kernel_time, proc_user_time;
        FILETIME parent_proc_creation_time, parent_proc_exit_time, parent_proc_kernel_time, parent_proc_user_time;
        if (GetProcessTimes(proc_handle, &proc_creation_time, &proc_exit_time, &proc_kernel_time, &proc_user_time) &&
          GetProcessTimes(parent_proc_handle, &parent_proc_creation_time, &parent_proc_exit_time, &parent_proc_kernel_time, &parent_proc_user_time)) {
          return (CompareFileTime(&proc_creation_time, &parent_proc_creation_time) == 1);
        }
      }
    }
    return false;
  }
  #elif (defined(__APPLE__) && defined(__MACH__))
  bool proc_id_and_parent_proc_id_compare_creation_time(proc_id_info::proc_id_t proc_id, proc_id_info::proc_id_t parent_proc_id) {
    return true; // TODO: Add proper platform-specific implementation...
  }
  #elif (defined(__linux__) || defined(__ANDROID__))
  bool proc_id_and_parent_proc_id_compare_creation_time(proc_id_info::proc_id_t proc_id, proc_id_info::proc_id_t parent_proc_id) {
    return true; // TODO: Add proper platform-specific implementation...
  }
  #elif (defined(__FreeBSD__) || defined(__FreeBSD_kernel__))
  bool proc_id_and_parent_proc_id_compare_creation_time(proc_id_info::proc_id_t proc_id, proc_id_info::proc_id_t parent_proc_id) {
    return true; // TODO: Add proper platform-specific implementation...
  }
  #elif defined(__DragonFly__)
  bool proc_id_and_parent_proc_id_compare_creation_time(proc_id_info::proc_id_t proc_id, proc_id_info::proc_id_t parent_proc_id) {
    return true; // TODO: Add proper platform-specific implementation...
  }
  #elif defined(__NetBSD__)
  bool proc_id_and_parent_proc_id_compare_creation_time(proc_id_info::proc_id_t proc_id, proc_id_info::proc_id_t parent_proc_id) {
    return true; // TODO: Add proper platform-specific implementation...
  }
  #elif defined(__OpenBSD__)
  bool proc_id_and_parent_proc_id_compare_creation_time(proc_id_info::proc_id_t proc_id, proc_id_info::proc_id_t parent_proc_id) {
    return true; // TODO: Add proper platform-specific implementation...
  }
  #elif (defined(__sun) && defined(__SVR4))
  bool proc_id_and_parent_proc_id_compare_creation_time(proc_id_info::proc_id_t proc_id, proc_id_info::proc_id_t parent_proc_id) {
    return true; // TODO: Add proper platform-specific implementation...
  }
  #endif

  #if (defined(_WIN32) || defined(_WIN64))
  bool proc_id_is_kernel_thread(proc_id_info::proc_id_t proc_id) {
    bool retval = false;
    HANDLE hp = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (!hp) return vec;
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hp, &pe)) {
      do {
        message_pump();
        if (pe.th32ProcessID == proc_id) {
          std::string comm = pe.szExeFile; std::size_t len = comm.length();
          retval = (!(len < 4 || (len >= 4 && !comm.substr(len - 4).compare(".exe"))));
          break;
        }
      } while (Process32Next(hp, &pe));
    }
    CloseHandle(hp);
    return retval;
  }
  #elif (defined(__linux__) || defined(__ANDROID__))
  bool proc_id_is_kernel_thread(proc_id_info::proc_id_t proc_id) {
    std::string procfs_path;
    if (proc_id == proc_id_info::proc_id_from_self()) {
      procfs_path = "/proc/self/stat";
    } else {
      procfs_path = std::string("/proc/") + std::to_string(proc_id) + std::string("/stat");
    }
    std::ifstream file(procfs_path);
    if (!file.is_open()) {
      return false;
    }
    std::string content;
    std::getline(file, content);
    size_t last_closing_parentheses = content.rfind(')');
    if (last_closing_parentheses == std::string::npos || last_closing_parentheses + 2 >= content.length()) {
      return false;
    }
    std::string rest_of_file = content.substr(last_closing_parentheses + 2);
    std::istringstream iss(rest_of_file);
    std::string token;
    int current_field_index = 3; 
    unsigned long flags = 0;
    while (iss >> token) {
      if (current_field_index == 9) {
        flags = strtoul(token.c_str(), nullptr, 10);
        break;
      }
      current_field_index++;
    }
    return (flags & PF_KTHREAD);
  }
  #elif (defined(__FreeBSD__) || defined(__FreeBSD_kernel__))
  bool proc_id_is_kernel_thread(proc_id_info::proc_id_t proc_id) {
    int cntp = 0;
    kvm_t *kd = nullptr;
    kinfo_proc *proc_info = nullptr;
    const char *nlistf = "/dev/null";
    const char *memf   = "/dev/null";
    kd = kvm_openfiles(nlistf, memf, nullptr, O_RDONLY, nullptr);
    if (!kd) return false;
    if ((proc_info = kvm_getprocs(kd, KERN_PROC_PID, proc_id, &cntp))) {
      bool retval = ((proc_info->ki_flag & P_SYSTEM) && proc_info->ki_pid != 1);
      kvm_close(kd);
      return retval;
    }
    return false;
  }
  #elif defined(__DragonFly__)
  bool proc_id_is_kernel_thread(proc_id_info::proc_id_t proc_id) {
    int cntp = 0;
    kvm_t *kd = nullptr;
    kinfo_proc *proc_info = nullptr;
    const char *nlistf = "/dev/null";
    const char *memf   = "/dev/null";
    kd = kvm_openfiles(nlistf, memf, nullptr, O_RDONLY, nullptr);
    if (!kd) return false;
    if ((proc_info = kvm_getprocs(kd, KERN_PROC_PID, proc_id, &cntp))) {
      bool retval = ((proc_info->kp_flags & P_SYSTEM) && proc_info->kp_pid != 1);
      kvm_close(kd);
      return retval;
    }
    return false;
  }
  #elif defined(__NetBSD__)
  bool proc_id_is_kernel_thread(proc_id_info::proc_id_t proc_id) {
    int cntp = 0;
    kvm_t *kd = nullptr;
    kinfo_proc2 *proc_info = nullptr;
    kd = kvm_openfiles(nullptr, nullptr, nullptr, KVM_NO_FILES, nullptr);
    if (!kd) return false;
    if ((proc_info = kvm_getproc2(kd, KERN_PROC_PID, proc_id, sizeof(struct kinfo_proc2), &cntp))) {
      bool retval = (proc_info->p_flag & P_SYSTEM);
      kvm_close(kd);
      return retval;
    }
    return false;
  }
  #elif defined(__OpenBSD__)
  bool proc_id_is_kernel_thread(proc_id_info::proc_id_t proc_id) {
    int cntp = 0;
    kvm_t *kd = nullptr;
    kinfo_proc *proc_info = nullptr;
    kd = kvm_openfiles(nullptr, nullptr, nullptr, KVM_NO_FILES, nullptr);
    if (!kd) return false;
    if ((proc_info = kvm_getprocs(kd, KERN_PROC_PID, proc_id, sizeof(struct kinfo_proc), &cntp))) {
      bool retval = (proc_info->p_flag & P_SYSTEM);
      kvm_close(kd);
      return retval;
    }
    return false;
  }
  #elif (defined(__sun) && defined(__SVR4))
  bool proc_id_is_kernel_thread(proc_id_info::proc_id_t proc_id) {
    auto proc_pstatus_get = [](pstatus_t *pstatus, proc_id_info::proc_id_t proc_id) {
      int fd = -1, retval = -1;
      std::string procfs_path;
      if (proc_id == proc_id_info::proc_id_from_self()) {
        procfs_path = "/proc/self/status";
      } else {
        procfs_path = std::string("/proc/") + std::to_string(proc_id) + std::string("/status");
      }
      if ((fd = open(procfs_path.c_str(), O_RDONLY)) != -1) {
        if (read(fd, pstatus, sizeof(*pstatus)) == sizeof(*pstatus)) {
          retval = 0;
        }
        close(fd);
      }
      return retval;
    };
    pstatus_t pstatus;
    if (!proc_pstatus_get(&pstatus, proc_id)) {
      return (pstatus.pr_flags & PR_ISSYS);
    }
    kvm_t *kd = nullptr;
    struct proc *proc_info = nullptr;
    kd = kvm_open(nullptr, nullptr, nullptr, O_RDONLY, nullptr);
    if (!kd) return false;
    if ((proc_info = kvm_getproc(kd, proc_id))) {
      bool retval = (proc_info->p_flag & SSYS);
      kvm_close(kd);
      return retval;
    }
    return false;
  }
  #endif

} // anonymous namespace

namespace proc_id_info {

  proc_id_t proc_id_from_self() {
    #if (!defined(_WIN32) && !defined(_WIN64))
    return getpid();
    #else
    return GetCurrentProcessId();
    #endif
  }

  std::vector<proc_id_t> proc_id_enum() {
    std::vector<proc_id_t> vec;
    #if (defined(_WIN32) || defined(_WIN64))
    HANDLE hp = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (!hp) return vec;
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hp, &pe)) {
      do {
        message_pump();
        // If the szExeFile member of the PROCESSENTRY32 structure has 
        // no *.exe file extension, that means it is a kernel thread...
        std::string comm = pe.szExeFile; std::size_t len = comm.length();
        if (len < 4 || (len >= 4 && !comm.substr(len - 4).compare(".exe"))) {
          vec.push_back(pe.th32ProcessID);
        }
      } while (Process32Next(hp, &pe));
    }
    CloseHandle(hp);
    #elif (defined(__APPLE__) && defined(__MACH__))
    std::vector<proc_id_t> proc_info;
    proc_info.resize(proc_listpids(PROC_ALL_PIDS, 0, nullptr, 0));
    // The proc_listpids(...) API does not include kernel threads...
    // Use the sysctl(...) API instead if you need to include kernel threads...
    int cntp = proc_listpids(PROC_ALL_PIDS, 0, &proc_info[0], sizeof(proc_id_t) * proc_info.size());
    for (int i = cntp - 1; i >= 0; i--) {
      if (proc_info[i] > 0) {
        vec.push_back(proc_info[i]);
      }
    }
    #elif ((defined(__linux__) || defined(__ANDROID__)) || (defined(__sun) && defined(__SVR4)))
    DIR *proc = opendir("/proc");
    if (!proc) return vec;
    struct dirent *ent = nullptr;
    proc_id_t tgid = 0;
    while ((ent = readdir(proc))) {
      if (isdigit(*ent->d_name)) {
        tgid = strtoul(ent->d_name, nullptr, 10);
        // Checks if the PF_KTHREAD flag is not present on Linux / Android...
        // Checks if the PR_ISSYS flag is not present on Solaris / illumos...
        // If these flags are not set then the process is not a kernel thread...
        if (!proc_id_is_kernel_thread(tgid)) {
          vec.push_back(tgid);
        }
      }
    }
    closedir(proc);
    #elif (defined(__FreeBSD__) || defined(__FreeBSD_kernel__))
    int cntp = 0;
    kvm_t *kd = nullptr;
    kinfo_proc *proc_info = nullptr;
    const char *nlistf = "/dev/null";
    const char *memf   = "/dev/null";
    kd = kvm_openfiles(nlistf, memf, nullptr, O_RDONLY, nullptr);
    if (!kd) return vec;
    // Using KERN_PROC_PROC instead of KERN_PROC_ALL on FreeBSD omits kernel threads...
    // Checking if the P_SYSTEM flag is not set on the iterated process does the same thing...
    if ((proc_info = kvm_getprocs(kd, KERN_PROC_PROC, 0, &cntp))) {
      for (int i = 0; i < cntp; i++) {
        // FreeBSD considers a PID of one to be a kernel thread for some reason...
        // For consistency with the other Unix-like platforms we do not omit a PID of one...
        // The Unix-like system init process, (a PID of one), is not a kernel thread...
        if (!(proc_info[i].ki_flag & P_SYSTEM) || proc_info[i].ki_pid == 1) {
          vec.push_back(proc_info[i].ki_pid);
        }
      }
    }
    kvm_close(kd);
    #elif defined(__DragonFly__)
    int cntp = 0;
    kvm_t *kd = nullptr;
    kinfo_proc *proc_info = nullptr;
    const char *nlistf = "/dev/null";
    const char *memf   = "/dev/null";
    kd = kvm_openfiles(nlistf, memf, nullptr, O_RDONLY, nullptr);
    if (!kd) return vec;
    if ((proc_info = kvm_getprocs(kd, KERN_PROC_ALL, 0, &cntp))) {
      for (int i = 0; i < cntp; i++) {
        // DragonFly BSD considers a PID of one to be a kernel thread for some reason...
        // For consistency with the other Unix-like platforms we do not omit a PID of one...
        // The Unix-like system init process, (a PID of one), is not a kernel thread...
        if (!(proc_info[i].kp_flags & P_SYSTEM) || proc_info[i].kp_pid == 1) {
          vec.push_back(proc_info[i].kp_pid);
        }
      }
    }
    kvm_close(kd);
    #elif defined(__NetBSD__)
    int cntp = 0;
    kvm_t *kd = nullptr;
    kinfo_proc2 *proc_info = nullptr;
    kd = kvm_openfiles(nullptr, nullptr, nullptr, KVM_NO_FILES, nullptr);
    if (!kd) return vec;
    if ((proc_info = kvm_getproc2(kd, KERN_PROC_ALL, 0, sizeof(struct kinfo_proc2), &cntp))) {
      for (int i = cntp - 1; i >= 0; i--) {
        if (!(proc_info[i].p_flag & P_SYSTEM)) {
          vec.push_back(proc_info[i].p_pid);
        }
      }
    }
    kvm_close(kd);
    #elif defined(__OpenBSD__)
    int cntp = 0;
    kvm_t *kd = nullptr;
    kinfo_proc *proc_info = nullptr;
    kd = kvm_openfiles(nullptr, nullptr, nullptr, KVM_NO_FILES, nullptr);
    if (!kd) return vec;
    // Using KERN_PROC_ALL instead of KERN_PROC_KTHREAD on OpenBSD omits kernel threads...
    // Checking if the P_SYSTEM flag is not set on the iterated process does the same thing...
    if ((proc_info = kvm_getprocs(kd, KERN_PROC_ALL, 0, sizeof(struct kinfo_proc), &cntp))) {
      for (int i = cntp - 1; i >= 0; i--) {
        if (!(proc_info[i].p_flag & P_SYSTEM)) {
          vec.push_back(proc_info[i].p_pid);
        }
      }
    }
    kvm_close(kd);
    #endif
    #if (defined(__sun) && defined(__SVR4))
    struct pid cur_pid;
    kvm_t *kd = nullptr;
    struct proc *proc_info = nullptr;
    if (!vec.empty()) { 
      goto finish;
    }
    kd = kvm_open(nullptr, nullptr, nullptr, O_RDONLY, nullptr);
    if (!kd) return vec;
    while ((proc_info = kvm_nextproc(kd))) {
      // The Solaris / illumos SSYS flag is basically the same thing as the P_SYSTEM flag on *BSD platforms...
      // If the SSYS flag is not set on the currently iterated process, that means it is not a kernel thread...
      if (!(proc_info->p_flag & SSYS)) {
        if (kvm_kread(kd, (std::uintptr_t)proc_info->p_pidp, &cur_pid, sizeof(cur_pid)) != -1) {
          vec.insert(vec.begin(), cur_pid.pid_id);
        }
      }
    }
    kvm_close(kd);
    finish:
    #endif
    #if (defined(_WIN32) || defined(_WIN64))
    // Removes a PID of four, (it is not a user-level process on Windows)...
    auto itr = std::remove(vec.begin(), vec.end(), 4);
    vec.erase(itr, vec.end());
    #endif
    // Removes a PID of zero, (it is not a user-level process)...
    auto itr = std::remove(vec.begin(), vec.end(), 0);
    vec.erase(itr, vec.end());
    std::sort(vec.begin(), vec.end());
    return vec;
  }

  bool proc_id_exists(proc_id_t proc_id) {
    #if (!defined(_WIN32) && !defined(_WIN64))
    if (proc_id < 0) return false;
    #endif
    std::vector<proc_id_t> vec = proc_id_enum();
    auto itr = std::find(vec.begin(), vec.end(), proc_id);
    return (itr != vec.end());
  }

  bool proc_id_suspend(proc_id_t proc_id) {
    #if (!defined(_WIN32) && !defined(_WIN64))
    if (proc_id < 0) return false;
    #endif
    #if (!defined(_WIN32) && !defined(_WIN64))
    return (!kill(proc_id, SIGSTOP));
    #else
    HANDLE proc = open_process_with_debug_privilege(proc_id);
    if (!proc) return false;
    typedef NTSTATUS (__stdcall *NTSP)(IN HANDLE ProcessHandle);
    HMODULE hModule = GetModuleHandleW(L"ntdll.dll");
    if (!hModule) return false;
    FARPROC farProc = GetProcAddress(hModule, "NtSuspendProcess");
    if (!farProc) return false;
    NTSP NtSuspendProcess = (NTSP)farProc;
    NTSTATUS status = NtSuspendProcess(proc);
    ULONG error = RtlNtStatusToDosError(status);
    CloseHandle(proc);
    return (!error);
    #endif
  }

  bool proc_id_resume(proc_id_t proc_id) {
    #if (!defined(_WIN32) && !defined(_WIN64))
    if (proc_id < 0) return false;
    #endif
    #if (!defined(_WIN32) && !defined(_WIN64))
    return (!kill(proc_id, SIGCONT));
    #else
    HANDLE proc = open_process_with_debug_privilege(proc_id);
    if (!proc) return false;
    typedef NTSTATUS (__stdcall *NTRP)(IN HANDLE ProcessHandle);
    HMODULE hModule = GetModuleHandleW(L"ntdll.dll");
    if (!hModule) return false;
    FARPROC farProc = GetProcAddress(hModule, "NtResumeProcess");
    if (!farProc) return false;
    NTRP NtResumeProcess = (NTRP)farProc;
    NTSTATUS status = NtResumeProcess(proc);
    ULONG error = RtlNtStatusToDosError(status);
    CloseHandle(proc);
    return (!error);
    #endif
  }

  bool proc_id_kill(proc_id_t proc_id) {
    #if (!defined(_WIN32) && !defined(_WIN64))
    if (proc_id < 0) return false;
    #endif
    #if (!defined(_WIN32) && !defined(_WIN64))
    return (!kill(proc_id, SIGKILL));
    #else
    HANDLE proc = open_process_with_debug_privilege(proc_id);
    if (!proc) return false;
    bool result = TerminateProcess(proc, 0);
    CloseHandle(proc);
    return result;
    #endif
  }

  std::vector<proc_id_t> parent_proc_id_from_proc_id(proc_id_t proc_id) {
    std::vector<proc_id_t> vec;
    #if (!defined(_WIN32) && !defined(_WIN64))
    if (proc_id < 0) return vec;
    #endif
    #if (defined(_WIN32) || defined(_WIN64))
    HANDLE hp = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (!hp) return vec;
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hp, &pe)) {
      do {
        message_pump();
        if (pe.th32ProcessID == proc_id) {
          // If the szExeFile member of the PROCESSENTRY32 structure has
          // no *.exe file extension, that means it is a kernel thread...
          std::string comm = pe.szExeFile; std::size_t len = comm.length();
          if (len < 4 || (len >= 4 && !comm.substr(len - 4).compare(".exe"))) {
            if (proc_id_and_parent_proc_id_compare_creation_time(pe.th32ProcessID, pe.th32ParentProcessID)) {
              vec.push_back(pe.th32ParentProcessID);
            }
          }
          break;
        }
      } while (Process32Next(hp, &pe));
    }
    CloseHandle(hp);
    struct is_invalid {
      bool operator()(proc_id_t proc_id) {
        return (proc_id_is_kernel_thread(proc_id));
      }
    };
    vec.erase(std::remove_if(vec.begin(), vec.end(), is_invalid()), vec.end());
    #elif (defined(__APPLE__) && defined(__MACH__))
    proc_bsdinfo proc_info;
    // The proc_pidinfo(...) API does not include kernel threads...
    // Use the sysctl(...) API instead if you need to include kernel threads...
    if (proc_pidinfo(proc_id, PROC_PIDTBSDINFO, 0, &proc_info, sizeof(proc_info)) > 0) {
      if (proc_id_and_parent_proc_id_compare_creation_time(proc_id, proc_info.pbi_ppid)) {
        vec.push_back(proc_info.pbi_ppid);
      }
    }
    #elif (defined(__linux__) || defined(__ANDROID__))
    // Checks if the PF_KTHREAD flag is not present on Linux / Android...
    // If this flag is not set then the process is not a kernel thread...
    if (!proc_id_is_kernel_thread(proc_id)) {
      char buffer[BUFSIZ];
      FILE *file = nullptr;
      std::string procfs_path;
      if (proc_id == proc_id_from_self()) {
        procfs_path = "/proc/self/stat";
      } else {
        procfs_path = std::string("/proc/") + std::to_string(proc_id) + std::string("/stat");
      }
      if ((file = fopen(procfs_path.c_str(), "r"))) {
        std::size_t size = fread(buffer, sizeof(char), sizeof(buffer), file);
        if (size > 0) {
          char *token = nullptr;
          if (((token = strtok(buffer, " "))) &&
            ((token = strtok(nullptr, " "))) &&
            ((token = strtok(nullptr, " "))) &&
            ((token = strtok(nullptr, " ")))) {
            proc_id_t parent_proc_id = strtoul(token, nullptr, 10);
            if (proc_id_and_parent_proc_id_compare_creation_time(proc_id, parent_proc_id)) {
              vec.push_back(parent_proc_id);
            }
          }
        }
        fclose(file);
      }
    }
    struct is_invalid {
      bool operator()(proc_id_t proc_id) {
        return (proc_id_is_kernel_thread(proc_id));
      }
    };
    vec.erase(std::remove_if(vec.begin(), vec.end(), is_invalid()), vec.end());
    #elif (defined(__FreeBSD__) || defined(__FreeBSD_kernel__))
    int cntp = 0;
    kvm_t *kd = nullptr;
    kinfo_proc *proc_info = nullptr;
    const char *nlistf = "/dev/null";
    const char *memf   = "/dev/null";
    kd = kvm_openfiles(nlistf, memf, nullptr, O_RDONLY, nullptr);
    if (!kd) return vec;
    if ((proc_info = kvm_getprocs(kd, KERN_PROC_PID, proc_id, &cntp))) {
      // FreeBSD considers a PID of one to be a kernel thread for some reason...
      // For consistency with the other Unix-like platforms we do not omit a PID of one...
      // The Unix-like system init process, (a PID of one), is not a kernel thread...
      if (!(proc_info->ki_flag & P_SYSTEM) || proc_info->ki_ppid == 1) {
        if (proc_id_and_parent_proc_id_compare_creation_time(proc_id, proc_info->ki_ppid)) {
          vec.push_back(proc_info->ki_ppid);
        }
      }
    }
    kvm_close(kd);
    struct is_invalid {
      bool operator()(proc_id_t proc_id) {
        return (proc_id_is_kernel_thread(proc_id));
      }
    };
    vec.erase(std::remove_if(vec.begin(), vec.end(), is_invalid()), vec.end());
    #elif defined(__DragonFly__)
    int cntp = 0;
    kvm_t *kd = nullptr;
    kinfo_proc *proc_info = nullptr;
    const char *nlistf = "/dev/null";
    const char *memf   = "/dev/null";
    kd = kvm_openfiles(nlistf, memf, nullptr, O_RDONLY, nullptr);
    if (!kd) return vec;
    if ((proc_info = kvm_getprocs(kd, KERN_PROC_PID, proc_id, &cntp))) {
      // DragonFly BSD considers a PID of one to be a kernel thread for some reason...
      // For consistency with the other Unix-like platforms we do not omit a PID of one...
      // The Unix-like system init process, (a PID of one), is not a kernel thread...
      if (!(proc_info->kp_flags & P_SYSTEM) || proc_info->kp_ppid == 1) {
        if (proc_id_and_parent_proc_id_compare_creation_time(proc_id, proc_info->kp_ppid)) {
          vec.push_back(proc_info->kp_ppid);
        }
      }
    }
    kvm_close(kd);
    struct is_invalid {
      bool operator()(proc_id_t proc_id) {
        return (proc_id_is_kernel_thread(proc_id));
      }
    };
    vec.erase(std::remove_if(vec.begin(), vec.end(), is_invalid()), vec.end());
    #elif defined(__NetBSD__)
    int cntp = 0;
    kvm_t *kd = nullptr;
    kinfo_proc2 *proc_info = nullptr;
    kd = kvm_openfiles(nullptr, nullptr, nullptr, KVM_NO_FILES, nullptr);
    if (!kd) return vec;
    if ((proc_info = kvm_getproc2(kd, KERN_PROC_PID, proc_id, sizeof(struct kinfo_proc2), &cntp))) {
      if (!(proc_info->p_flag & P_SYSTEM)) {
        if (proc_id_and_parent_proc_id_compare_creation_time(proc_id, proc_info->p_ppid)) {
          vec.push_back(proc_info->p_ppid);
        }
      }
    }
    kvm_close(kd);
    struct is_invalid {
      bool operator()(proc_id_t proc_id) {
        return (proc_id_is_kernel_thread(proc_id));
      }
    };
    vec.erase(std::remove_if(vec.begin(), vec.end(), is_invalid()), vec.end());
    #elif defined(__OpenBSD__)
    int cntp = 0;
    kvm_t *kd = nullptr;
    kinfo_proc *proc_info = nullptr;
    kd = kvm_openfiles(nullptr, nullptr, nullptr, KVM_NO_FILES, nullptr);
    if (!kd) return vec;
    if ((proc_info = kvm_getprocs(kd, KERN_PROC_PID, proc_id, sizeof(struct kinfo_proc), &cntp))) {
      if (!(proc_info->p_flag & P_SYSTEM)) {
        if (proc_id_and_parent_proc_id_compare_creation_time(proc_id, proc_info->p_ppid)) {
          vec.push_back(proc_info->p_ppid);
        }
      }
    }
    kvm_close(kd);
    struct is_invalid {
      bool operator()(proc_id_t proc_id) {
        return (proc_id_is_kernel_thread(proc_id));
      }
    };
    vec.erase(std::remove_if(vec.begin(), vec.end(), is_invalid()), vec.end());
    #elif (defined(__sun) && defined(__SVR4))
    // Checks if the PR_ISSYS flag is not present on Solaris / illumos...
    // If this flag is not set then the process is not a kernel thread...
    if (!proc_id_is_kernel_thread(proc_id)) {
      int fd = -1;
      pstatus_t status;
      std::string procfs_path;
      if (proc_id == proc_id_from_self()) {
        procfs_path = "/proc/self/status";
      } else {
        procfs_path = std::string("/proc/") + std::to_string(proc_id) + std::string("/status");
      }
      if ((fd = open(procfs_path.c_str(), O_RDONLY)) != -1) {
        if (read(fd, &status, sizeof(pstatus_t)) > 0) {
          vec.push_back(status.pr_ppid);
        }
        close(fd);
      }
    }
    kvm_t *kd = nullptr;
    struct proc *proc_info = nullptr;
    if (!vec.empty()) { 
      goto finish;
    }
    kd = kvm_open(nullptr, nullptr, nullptr, O_RDONLY, nullptr);
    if (!kd) return vec;
    if ((proc_info = kvm_getproc(kd, proc_id))) {
      // The Solaris / illumos SSYS flag is basically the same thing as the P_SYSTEM flag on *BSD platforms...
      // If the SSYS flag is not set on the currently iterated process, that means it is not a kernel thread...
      if (!(proc_info->p_flag & SSYS)) {
        if (proc_id_and_parent_proc_id_compare_creation_time(proc_id, proc_info->p_ppid)) {
          vec.push_back(proc_info->p_ppid);
        }
      }
    }
    kvm_close(kd);
    struct is_invalid {
      bool operator()(proc_id_t proc_id) {
        return (proc_id_is_kernel_thread(proc_id));
      }
    };
    vec.erase(std::remove_if(vec.begin(), vec.end(), is_invalid()), vec.end());
    finish:
    #endif
    #if (defined(_WIN32) || defined(_WIN64))
    // Removes a PID of four, (it is not a user-level process on Windows)...
    if (!vec.empty() && vec[0] == 4) {
      vec.clear();
    }
    #endif
    // Removes a PID of zero, (it is not a user-level process)...
    if (!vec.empty() && vec[0] == 0) {
      vec.clear();
    }
    return vec;
  }

  std::vector<proc_id_t> proc_id_from_parent_proc_id(proc_id_t parent_proc_id) {
    std::vector<proc_id_t> vec;
    #if (!defined(_WIN32) && !defined(_WIN64))
    if (parent_proc_id < 0) return vec;
    #endif
    #if (defined(_WIN32) || defined(_WIN64))
    HANDLE hp = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (!hp) return vec;
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hp, &pe)) {
      do {
        message_pump();
        if (pe.th32ParentProcessID == parent_proc_id) {
          // If the szExeFile member of the PROCESSENTRY32 structure has
          // no *.exe file extension, that means it is a kernel thread...
          std::string comm = pe.szExeFile; std::size_t len = comm.length();
          if (len < 4 || (len >= 4 && !comm.substr(len - 4).compare(".exe"))) {
            if (proc_id_and_parent_proc_id_compare_creation_time(pe.th32ProcessID, pe.th32ParentProcessID)) {
              vec.push_back(pe.th32ProcessID);
            }
          }
        }
      } while (Process32Next(hp, &pe));
    }
    CloseHandle(hp);
    struct is_invalid {
      bool operator()(proc_id_t proc_id) {
        return (proc_id_is_kernel_thread(proc_id));
      }
    };
    vec.erase(std::remove_if(vec.begin(), vec.end(), is_invalid()), vec.end());
    #elif (defined(__APPLE__) && defined(__MACH__))
    std::vector<proc_id_t> proc_info;
    proc_info.resize(proc_listpids(PROC_PPID_ONLY, (uint32_t)parent_proc_id, nullptr, 0));
    // The proc_listpids(...) API does not include kernel threads...
    // Use the sysctl(...) API instead if you need to include kernel threads...
    int cntp = proc_listpids(PROC_PPID_ONLY, (uint32_t)parent_proc_id, &proc_info[0], sizeof(proc_id_t) * proc_info.size());
    for (int i = cntp - 1; i >= 0; i--) {
      if (proc_info[i] > 0) {
        if (proc_id_and_parent_proc_id_compare_creation_time(proc_info[i], parent_proc_id)) {
          vec.push_back(proc_info[i]);
        }
      }
    }
    #elif ((defined(__linux__) || defined(__ANDROID__)) || (defined(__sun) && defined(__SVR4)))
    DIR *proc = opendir("/proc");
    if (!proc) return vec;
    struct dirent *ent = nullptr;
    proc_id_t tgid = 0;
    while ((ent = readdir(proc))) {
      if (isdigit(*ent->d_name)) {
        tgid = strtoul(ent->d_name, nullptr, 10);
        // Checks if the PF_KTHREAD flag is not present on Linux / Android...
        // Checks if the PR_ISSYS flag is not present on Solaris / illumos...
        // If these flags are not set then the process is not a kernel thread...
        if (!proc_id_is_kernel_thread(tgid)) {
          std::vector<proc_id_t> proc_info = parent_proc_id_from_proc_id(tgid);
          if (!proc_info.empty() && proc_info[0] == parent_proc_id) {
            if (proc_id_and_parent_proc_id_compare_creation_time(tgid, proc_info[0])) {
              vec.push_back(tgid);
            }
          }
        }
      }
    }
    closedir(proc);
    struct is_invalid {
      bool operator()(proc_id_t proc_id) {
        return (proc_id_is_kernel_thread(proc_id));
      }
    };
    vec.erase(std::remove_if(vec.begin(), vec.end(), is_invalid()), vec.end());
    #elif (defined(__FreeBSD__) || defined(__FreeBSD_kernel__))
    int cntp = 0;
    kvm_t *kd = nullptr;
    kinfo_proc *proc_info = nullptr;
    const char *nlistf = "/dev/null";
    const char *memf   = "/dev/null";
    kd = kvm_openfiles(nlistf, memf, nullptr, O_RDONLY, nullptr);
    if (!kd) return vec;
    // Using KERN_PROC_PROC instead of KERN_PROC_ALL on FreeBSD omits kernel threads...
    // Checking if the P_SYSTEM flag is not set on the iterated process does the same thing...
    if ((proc_info = kvm_getprocs(kd, KERN_PROC_PROC, 0, &cntp))) {
      for (int i = 0; i < cntp; i++) {
        // FreeBSD considers a PID of one to be a kernel thread for some reason...
        // For consistency with the other Unix-like platforms we do not omit a PID of one...
        // The Unix-like system init process, (a PID of one), is not a kernel thread...
        if (!(proc_info[i].ki_flag & P_SYSTEM) || proc_info[i].ki_ppid == 1) {
          if (proc_info[i].ki_ppid == parent_proc_id) {
            if (proc_id_and_parent_proc_id_compare_creation_time(proc_info[i].ki_pid, proc_info[i].ki_ppid)) {
              vec.push_back(proc_info[i].ki_pid);
            }
          }
        }
      }
    }
    kvm_close(kd);
    struct is_invalid {
      bool operator()(proc_id_t proc_id) {
        return (proc_id_is_kernel_thread(proc_id));
      }
    };
    vec.erase(std::remove_if(vec.begin(), vec.end(), is_invalid()), vec.end());
    #elif defined(__DragonFly__)
    int cntp = 0;
    kvm_t *kd = nullptr;
    kinfo_proc *proc_info = nullptr;
    const char *nlistf = "/dev/null";
    const char *memf   = "/dev/null";
    kd = kvm_openfiles(nlistf, memf, nullptr, O_RDONLY, nullptr);
    if (!kd) return vec;
    if ((proc_info = kvm_getprocs(kd, KERN_PROC_ALL, 0, &cntp))) {
      for (int i = 0; i < cntp; i++) {
        // DragonFly BSD considers a PID of one to be a kernel thread for some reason...
        // For consistency with the other Unix-like platforms we do not omit a PID of one...
        // The Unix-like system init process, (a PID of one), is not a kernel thread...
        if (!(proc_info[i].kp_flags & P_SYSTEM) || proc_info[i].kp_ppid == 1) {
          if (proc_info[i].kp_ppid == parent_proc_id) {
            if (proc_id_and_parent_proc_id_compare_creation_time(proc_info[i].kp_pid, proc_info[i].kp_ppid)) {
              vec.push_back(proc_info[i].kp_pid);
            }
          }
        }
      }
    }
    kvm_close(kd);
    struct is_invalid {
      bool operator()(proc_id_t proc_id) {
        return (proc_id_is_kernel_thread(proc_id));
      }
    };
    vec.erase(std::remove_if(vec.begin(), vec.end(), is_invalid()), vec.end());
    #elif defined(__NetBSD__)
    int cntp = 0;
    kvm_t *kd = nullptr;
    kinfo_proc2 *proc_info = nullptr;
    kd = kvm_openfiles(nullptr, nullptr, nullptr, KVM_NO_FILES, nullptr);
    if (!kd) return vec;
    if ((proc_info = kvm_getproc2(kd, KERN_PROC_ALL, 0, sizeof(struct kinfo_proc2), &cntp))) {
      for (int i = cntp - 1; i >= 0; i--) {
        if (!(proc_info[i].p_flag & P_SYSTEM)) {
          if (proc_info[i].p_ppid == parent_proc_id) {
            if (proc_id_and_parent_proc_id_compare_creation_time(proc_info[i].p_pid, proc_info[i].p_ppid)) {
              vec.push_back(proc_info[i].p_pid);
            }
          }
        }
      }
    }
    kvm_close(kd);
    struct is_invalid {
      bool operator()(proc_id_t proc_id) {
        return (proc_id_is_kernel_thread(proc_id));
      }
    };
    vec.erase(std::remove_if(vec.begin(), vec.end(), is_invalid()), vec.end());
    #elif defined(__OpenBSD__)
    int cntp = 0;
    kvm_t *kd = nullptr;
    kinfo_proc *proc_info = nullptr;
    kd = kvm_openfiles(nullptr, nullptr, nullptr, KVM_NO_FILES, nullptr);
    if (!kd) return vec;
    // Using KERN_PROC_ALL instead of KERN_PROC_KTHREAD on OpenBSD omits kernel threads...
    // Checking if the P_SYSTEM flag is not set on the iterated process does the same thing...
    if ((proc_info = kvm_getprocs(kd, KERN_PROC_ALL, 0, sizeof(struct kinfo_proc), &cntp))) {
      for (int i = cntp - 1; i >= 0; i--) {
        if (!(proc_info[i].p_flag & P_SYSTEM)) {
          if (proc_info[i].p_ppid == parent_proc_id) {
            if (proc_id_and_parent_proc_id_compare_creation_time(proc_info[i].p_pid, proc_info[i].p_ppid)) {
              vec.push_back(proc_info[i].p_pid);
            }
          }
        }
      }
    }
    kvm_close(kd);
    struct is_invalid {
      bool operator()(proc_id_t proc_id) {
        return (proc_id_is_kernel_thread(proc_id));
      }
    };
    vec.erase(std::remove_if(vec.begin(), vec.end(), is_invalid()), vec.end());
    #endif
    #if (defined(__sun) && defined(__SVR4))
    struct pid cur_pid;
    kvm_t *kd = nullptr;
    struct proc *proc_info = nullptr;
    if (!vec.empty()) { 
      goto finish;
    }
    kd = kvm_open(nullptr, nullptr, nullptr, O_RDONLY, nullptr);
    if (!kd) return vec;
    while ((proc_info = kvm_nextproc(kd))) {
      // The Solaris / illumos SSYS flag is basically the same thing as the P_SYSTEM flag on *BSD platforms...
      // If the SSYS flag is not set on the currently iterated process, that means it is not a kernel thread...
      if (!(proc_info->p_flag & SSYS)) {
        if (proc_info->p_ppid == parent_proc_id) {
          if (kvm_kread(kd, (std::uintptr_t)proc_info->p_pidp, &cur_pid, sizeof(cur_pid)) != -1) {
            if (proc_id_and_parent_proc_id_compare_creation_time(cur_pid.pid_id, proc_info->p_ppid)) {
              vec.insert(vec.begin(), cur_pid.pid_id);
            }
          }
        }
      }
    }
    kvm_close(kd);
    struct is_invalid {
      bool operator()(proc_id_t proc_id) {
        return (proc_id_is_kernel_thread(proc_id));
      }
    };
    vec.erase(std::remove_if(vec.begin(), vec.end(), is_invalid()), vec.end());
    finish:
    #endif
    #if (defined(_WIN32) || defined(_WIN64))
    // Removes a PID of four, (it is not a user-level process on Windows)...
    auto itr = std::remove(vec.begin(), vec.end(), 4);
    vec.erase(itr, vec.end());
    #endif
    // Removes a PID of zero, (it is not a user-level process)...
    auto itr = std::remove(vec.begin(), vec.end(), 0);
    vec.erase(itr, vec.end());
    std::sort(vec.begin(), vec.end());
    return vec;
  }

  std::string exe_from_proc_id(proc_id_t proc_id) {
    std::string path;
    #if (!defined(_WIN32) && !defined(_WIN64))
    if (proc_id < 0) return path;
    #endif
    #if (defined(_WIN32) || defined(_WIN64))
    if (proc_id == proc_id_from_self()) {
      wchar_t buffer[MAX_PATH];
      if (GetModuleFileNameW(nullptr, buffer, sizeof(buffer))) {
        wchar_t exe[MAX_PATH];
        if (_wrealpath(buffer, exe)) {
          path = narrow(exe);
        }
      }
    } else {
      HANDLE proc = open_process_with_debug_privilege(proc_id);
      if (!proc) return path;
      wchar_t buffer[MAX_PATH];
      unsigned long size = sizeof(buffer);
      if (QueryFullProcessImageNameW(proc, 0, buffer, &size)) {
        wchar_t exe[MAX_PATH];
        if (_wrealpath(buffer, exe)) {
          path = narrow(exe);
        }
      }
      CloseHandle(proc);
    }
    #elif (defined(__APPLE__) && defined(__MACH__))
    if (proc_id == proc_id_from_self()) {
      char buffer[PATH_MAX];
      std::uint32_t size = sizeof(buffer);
      if (!_NSGetExecutablePath(buffer, &size)) {
        char exe[PATH_MAX];
        if (realpath(buffer, exe)) {
          path = exe;
        }
      }
    } else {
      char buffer[PROC_PIDPATHINFO_MAXSIZE];
      if (proc_pidpath(proc_id, buffer, sizeof(buffer)) > 0) {
        char exe[PATH_MAX];
        if (realpath(buffer, exe)) {
          path = exe;
        }
      }
    }
    #elif (defined(__linux__) || defined(__ANDROID__))
    char exe[PATH_MAX];
    if (proc_id == proc_id_from_self()) {
      if (realpath("/proc/self/exe", exe)) {
        path = exe;
      }
    } else {
      if (realpath((std::string("/proc/") + std::to_string(proc_id) + 
        std::string("/exe")).c_str(), exe)) {
        path = exe;
      }
    }
    #elif ((defined(__FreeBSD__) || defined(__FreeBSD_kernel__)) || defined(__DragonFly__))
    int mib[4];
    std::size_t len = 0;
    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_PATHNAME;
    mib[3] = proc_id;
    if (!sysctl(mib, 4, nullptr, &len, nullptr, 0)) {
      std::vector<char> vecbuff;
      vecbuff.resize(len);
      char *buffer = &vecbuff[0];
      if (!sysctl(mib, 4, buffer, &len, nullptr, 0)) {
        char exe[PATH_MAX];
        if (realpath(buffer, exe)) {
          path = exe;
        }
      }
    }
    #elif defined(__NetBSD__)
    int mib[4];
    std::size_t len = 0;
    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC_ARGS;
    mib[2] = proc_id;
    mib[3] = KERN_PROC_PATHNAME;
    if (!sysctl(mib, 4, nullptr, &len, nullptr, 0)) {
      std::vector<char> vecbuff;
      vecbuff.resize(len);
      char *buffer = &vecbuff[0];
      if (!sysctl(mib, 4, buffer, &len, nullptr, 0)) {
        char exe[PATH_MAX];
        if (realpath(buffer, exe)) {
          path = exe;
        }
      }
    }
    #elif defined(__OpenBSD__)
    auto verify_exe = [](proc_id_t proc_id, std::string exe) {
      int cntp = 0;
      std::string res;
      kvm_t *kd = nullptr;
      kinfo_file *kif = nullptr;
      bool error1 = false, error2 = false;
      kd = kvm_openfiles(nullptr, nullptr, nullptr, KVM_NO_FILES, nullptr);
      if (kd) {
        if ((kif = kvm_getfiles(kd, KERN_FILE_BYPID, proc_id, sizeof(struct kinfo_file), &cntp))) {
          for (int i = 0; i < cntp && kif[i].fd_fd < 0; i++) {
            if (kif[i].fd_fd == KERN_FILE_TEXT) {
              fallback:
              struct stat st;
              char buffer[PATH_MAX];
              if (!stat(exe.c_str(), &st) && (st.st_mode & S_IXUSR) &&
                S_ISREG(st.st_mode) && realpath(exe.c_str(), buffer) &&
                st.st_dev == (dev_t)kif[i].va_fsid && st.st_ino == (ino_t)kif[i].va_fileid) {
                res = buffer;
              }
              if (res.empty() && !error1) {
                error1 = true;
                std::size_t last_slash_pos = exe.find_last_of("/");
                if (last_slash_pos != std::string::npos) {
                  exe = exe.substr(0, last_slash_pos + 1) + kif[i].p_comm;
                  goto fallback;
                }
              }
              if (res.empty() && !error2 && proc_id == proc_id_from_self()) {
                error2 = true;
                std::size_t last_slash_pos = exe.find_last_of("/");
                if (last_slash_pos != std::string::npos) {
                  const char *progname = getprogname();
                  if (progname) {
                    exe = exe.substr(0, last_slash_pos + 1) + progname;
                    goto fallback;
                  }
                }
              }
              break;
            }
          }
        }
        kvm_close(kd);
      }
      return res;
    };
    std::string argv0;
    bool argv0_does_not_exist = false;
    std::size_t slash_pos = std::string::npos;
    std::size_t colon_pos = std::string::npos;
    std::vector<std::string> cmdline = cmdline_from_proc_id(proc_id); 
    std::string buffer = ((!cmdline.empty() && !cmdline[0].empty()) ? cmdline[0] : "");
    bool error = false, retried = false, leading_dash_removed = false;
    if (buffer.empty()) {
      argv0_does_not_exist = true;
      goto path_lookup;
    } else {
      fallback:
      slash_pos = buffer.find('/');
      colon_pos = buffer.find(':');
      if (slash_pos == 0) {
        argv0 = buffer;
        path = verify_exe(proc_id, argv0);
      } else if (slash_pos == std::string::npos || (colon_pos != std::string::npos && colon_pos > 0 && slash_pos > colon_pos)) {
        path_lookup:
        retry_without_leading_dash:
        std::string penv = envvar_value_from_proc_id(proc_id, "PATH");
        if (!penv.empty()) {
          retry:
          std::string tmp;
          std::stringstream sstr(penv);
          while (std::getline(sstr, tmp, ':')) {
            argv0 = tmp + "/" + buffer;
            path = verify_exe(proc_id, argv0);
            if (!path.empty()) break;
            if (!argv0_does_not_exist && colon_pos != std::string::npos && colon_pos > 0 && slash_pos > colon_pos) {
              argv0 = tmp + "/" + buffer.substr(0, colon_pos);
              path = verify_exe(proc_id, argv0);
              if (!path.empty()) break;
            }
          }
        }
        if (path.empty() && !retried) {
          retried = true;
          penv = "/usr/bin:/bin:/usr/sbin:/sbin:/usr/X11R6/bin:/usr/local/bin:/usr/local/sbin";
          std::string home = envvar_value_from_proc_id(proc_id, "HOME");
          if (!home.empty()) {
            penv = home + "/bin:" + penv;
          }
          goto retry;
        }
        if (path.empty() && !argv0_does_not_exist && !leading_dash_removed && slash_pos == std::string::npos && buffer.length() > 1 && buffer[0] == '-') {
          buffer = buffer.substr(1);
          retried = false;
          leading_dash_removed = true;
          goto retry_without_leading_dash;
        }
      }
      if (path.empty() && (argv0_does_not_exist || (slash_pos != std::string::npos && slash_pos > 0))) {
        std::string pwd = envvar_value_from_proc_id(proc_id, "PWD");
        if (!pwd.empty()) {
          argv0 = pwd + "/" + buffer;
          path = verify_exe(proc_id, argv0);
        }
        if (path.empty()) {
          std::string cwd = cwd_from_proc_id(proc_id);
          if (!cwd.empty()) {
            argv0 = cwd + "/" + buffer;
            path = verify_exe(proc_id, argv0);
          }
        }
      }
      if (path.empty() && !error) {
        error = true;
        buffer.clear();
        std::string underscore = envvar_value_from_proc_id(proc_id, "_");
        if (!underscore.empty()) {
          buffer = underscore;
          leading_dash_removed = false;
          retried = false;
          goto fallback;
        }
      }
    }
    if (path.empty() && !argv0_does_not_exist) {
      argv0_does_not_exist = true;
      retried = false;
      buffer.clear();
      goto path_lookup;
    }
    #elif (defined(__sun) && defined(__SVR4))
    if (proc_id == proc_id_from_self()) {
      const char *execname = getexecname();
      if (execname) {
        char exe[PATH_MAX];
        if (realpath(execname, exe)) {
          path = exe;
        }
      }
    } else {
      int err = 0;
      char buffer[PATH_MAX];
      struct ps_prochandle *P = nullptr;
      P = Pgrab(proc_id, PGRAB_RDONLY, &err);
      if (P) {
        if (!err) {
          if (Pexecname(P, buffer, sizeof(buffer))) {
            char exe[PATH_MAX];
            if (realpath(buffer, exe)) {
              path = exe;
            }
          }
        }
        Pfree(P);
      }
    }
    if (path.empty()) {
      char exe[PATH_MAX];
      if (proc_id == proc_id_from_self()) {
        if (realpath("/proc/self/path/a.out", exe)) {
          path = exe;
        }
      } else {
        if (realpath((std::string("/proc/") + std::to_string(proc_id) + 
          std::string("/path/a.out")).c_str(), exe)) {
          path = exe;
        }
      }
    }
    #endif
    return path;
  }

  std::string cwd_from_proc_id(proc_id_t proc_id) {
    std::string path;
    #if (!defined(_WIN32) && !defined(_WIN64))
    if (proc_id < 0) return path;
    #endif
    #if (defined(_WIN32) || defined(_WIN64))
    if (proc_id == proc_id_from_self()) {
      wchar_t buffer[MAX_PATH];
      if (GetCurrentDirectoryW(MAX_PATH, buffer)) {
        wchar_t cwd[MAX_PATH];
        if (_wrealpath(buffer, cwd)) {
          path = narrow(cwd);
        }
      }
    } else {
      HANDLE proc = open_process_with_debug_privilege(proc_id);
      if (!proc) return path;
      std::vector<wchar_t> buffer1 = cmd_env_cwd_from_proc(proc, MEMCWD);
      if (!buffer1.empty()) {
        std::wstring buffer2 = &buffer1[0];
        if (!buffer2.empty() && std::count(buffer2.begin(), buffer2.end(), '\\') > 1 && buffer2.back() == '\\') {
          buffer2 = buffer2.substr(0, buffer2.length() - 1);
          wchar_t cwd[MAX_PATH];
          if (_wrealpath(buffer2.c_str(), cwd)) {
            path = narrow(cwd);
          }
        }
      }
      CloseHandle(proc);
    }
    #elif (defined(__APPLE__) && defined(__MACH__))
    if (proc_id == proc_id_from_self()) {
      char buffer[PATH_MAX];
      if (getcwd(buffer, PATH_MAX)) {
        char cwd[PATH_MAX];
        if (realpath(buffer, cwd)) {
           path = cwd;
        }
      }
    } else {
      proc_vnodepathinfo vpi;
      if (proc_pidinfo(proc_id, PROC_PIDVNODEPATHINFO, 0, &vpi, sizeof(vpi)) > 0) {
        char cwd[PATH_MAX];
        if (realpath(vpi.pvi_cdir.vip_path, cwd)) {
          path = cwd;
        }
      }
    }
    #elif (defined(__linux__) || defined(__ANDROID__))
    if (proc_id == proc_id_from_self()) {
      char buffer[PATH_MAX];
      if (getcwd(buffer, PATH_MAX)) {
        char cwd[PATH_MAX];
        if (realpath(buffer, cwd)) {
           path = cwd;
        }
      }
    } else {
      char cwd[PATH_MAX];
      if (realpath((std::string("/proc/") + std::to_string(proc_id) + 
        std::string("/cwd")).c_str(), cwd)) {
        path = cwd;
      }
    }
    #elif (defined(__FreeBSD__) || defined(__FreeBSD_kernel__))
    if (proc_id == proc_id_from_self()) {
      char buffer[PATH_MAX];
      if (getcwd(buffer, PATH_MAX)) {
        char cwd[PATH_MAX];
        if (realpath(buffer, cwd)) {
           path = cwd;
        }
      }
    } else {
      int mib[4];
      struct kinfo_file kif;
      std::size_t len = sizeof(kif);
      mib[0] = CTL_KERN;
      mib[1] = KERN_PROC;
      mib[2] = KERN_PROC_CWD;
      mib[3] = proc_id;
      if (!sysctl(mib, 4, nullptr, &len, nullptr, 0)) {
        memset(&kif, 0, len);
        if (!sysctl(mib, 4, &kif, &len, nullptr, 0)) {
          char cwd[PATH_MAX];
          if (realpath(kif.kf_path, cwd)) {
             path = cwd;
          }
        }
      }
    }
    #elif defined(__DragonFly__)
    if (proc_id == proc_id_from_self()) {
      char buffer[PATH_MAX];
      if (getcwd(buffer, PATH_MAX)) {
        char cwd[PATH_MAX];
        if (realpath(buffer, cwd)) {
           path = cwd;
        }
      }
    } else {
      int mib[4];
      char buffer[PATH_MAX];
      std::size_t len = sizeof(buffer);
      mib[0] = CTL_KERN;
      mib[1] = KERN_PROC;
      mib[2] = KERN_PROC_CWD;
      mib[3] = proc_id;
      if (!sysctl(mib, 4, buffer, &len, nullptr, 0)) {
        char cwd[PATH_MAX];
        if (realpath(buffer, cwd)) {
          path = cwd;
        }
      }
    }
    #elif defined(__NetBSD__)
    if (proc_id == proc_id_from_self()) {
      char buffer[PATH_MAX];
      if (getcwd(buffer, PATH_MAX)) {
        char cwd[PATH_MAX];
        if (realpath(buffer, cwd)) {
           path = cwd;
        }
      }
    } else {
      int mib[4];
      std::size_t len = 0;
      mib[0] = CTL_KERN;
      mib[1] = KERN_PROC_ARGS;
      mib[2] = proc_id;
      mib[3] = KERN_PROC_CWD;
      if (!sysctl(mib, 4, nullptr, &len, nullptr, 0)) {
        std::vector<char> vecbuff;
        vecbuff.resize(len);
        char *buffer = &vecbuff[0];
        if (!sysctl(mib, 4, buffer, &len, nullptr, 0)) {
          char cwd[PATH_MAX];
          if (realpath(buffer, cwd)) {
            path = cwd;
          }
        }
      }
    }
    #elif defined(__OpenBSD__)
    if (proc_id == proc_id_from_self()) {
      char buffer[PATH_MAX];
      if (getcwd(buffer, PATH_MAX)) {
        char cwd[PATH_MAX];
        if (realpath(buffer, cwd)) {
           path = cwd;
        }
      }
    } else {
      int mib[3];
      std::size_t len = 0;
      mib[0] = CTL_KERN;
      mib[1] = KERN_PROC_CWD;
      mib[2] = proc_id;
      if (!sysctl(mib, 3, nullptr, &len, nullptr, 0)) {
        std::vector<char> vecbuff;
        vecbuff.resize(len);
        char *buffer = &vecbuff[0];
        if (!sysctl(mib, 3, buffer, &len, nullptr, 0)) {
          char cwd[PATH_MAX];
          if (realpath(buffer, cwd)) {
            path = cwd;
          }
        }
      }
    }
    #elif (defined(__sun) && defined(__SVR4))
    if (proc_id == proc_id_from_self()) {
      char buffer[PATH_MAX];
      if (getcwd(buffer, PATH_MAX)) {
        char cwd[PATH_MAX];
        if (realpath(buffer, cwd)) {
           path = cwd;
        }
      }
    } else {
      // __illumos__ macro is not defined by the OS and 
      // should be added manually by your build system:
      #if defined(__illumos__)
      int err = 0;
      struct ps_prochandle *P = nullptr;
      P = Pgrab(proc_id, PGRAB_RDONLY, &err);
      if (P) {
        if (!err) {
          prcwd_t *ptr = nullptr;
          if (!Pcwd(P, &ptr)) {
            char cwd[PATH_MAX];
            if (realpath(ptr->prcwd_cwd, cwd)) {
              path = cwd;
            }
            Pcwd_free(ptr);
          }
        }
        Pfree(P);
        if (!path.empty()) {
          return path;
        }
      }
      #endif
      char cwd[PATH_MAX];
      if (realpath((std::string("/proc/") + std::to_string(proc_id) + 
        std::string("/path/cwd")).c_str(), cwd)) {
        path = cwd;
      }
    }
    #endif
    return path;
  }

  std::string comm_from_proc_id(proc_id_t proc_id) {
    std::string comm = exe_from_proc_id(proc_id);
    if (comm.empty()) return "";
    #if (!defined(_WIN32) && !defined(_WIN64))
    std::size_t pos = comm.find_last_of("/");
    #else
    std::size_t pos = comm.find_last_of("\\/");
    #endif
    if (pos != std::string::npos) {
      return comm.substr(pos + 1);
    }
    return comm;
  }

  std::vector<std::string> cmdline_from_proc_id(proc_id_t proc_id) {
    std::vector<std::string> vec;
    #if (!defined(_WIN32) && !defined(_WIN64))
    if (proc_id < 0) return vec;
    #endif
    #if (defined(_WIN32) || defined(_WIN64))
    HANDLE proc = open_process_with_debug_privilege(proc_id);
    if (!proc) return vec;
    int cmdsize = 0;
    std::vector<wchar_t> buffer = cmd_env_cwd_from_proc(proc, MEMCMD);
    if (!buffer.empty()) {
      wchar_t **cmd = CommandLineToArgvW(&buffer[0], &cmdsize);
      if (cmd) {
        for (int i = 0; i < cmdsize; i++) {
          message_pump();
          vec.push_back(narrow(cmd[i]));
        }
        LocalFree(cmd);
      }
    }
    CloseHandle(proc);
    #elif (defined(__APPLE__) && defined(__MACH__))
    vec = cmd_env_from_proc_id(proc_id, MEMCMD);
    #elif ((defined(__linux__) || defined(__ANDROID__)) || (defined(__sun) && defined(__SVR4)))
    FILE *file = nullptr;
    std::string procfs_path;
    if (proc_id == proc_id_from_self()) {
      procfs_path = "/proc/self/cmdline";
    } else {
      procfs_path = std::string("/proc/") + std::to_string(proc_id) + std::string("/cmdline");
    }
    if ((file = fopen(procfs_path.c_str(), "r"))) {
      char *cmd = nullptr;
      std::size_t size = 0;
      while (getdelim(&cmd, &size, 0, file) != -1) {
        vec.push_back(cmd);
      }
      while (!vec.empty() && vec.back().empty())
        vec.pop_back();
      if (cmd) free(cmd);
      fclose(file);
    }
    #elif ((defined(__FreeBSD__) || defined(__FreeBSD_kernel__)) || defined(__DragonFly__))
    int cntp = 0;
    kvm_t *kd = nullptr;
    kinfo_proc *proc_info = nullptr;
    const char *nlistf = "/dev/null";
    const char *memf   = "/dev/null";
    kd = kvm_openfiles(nlistf, memf, nullptr, O_RDONLY, nullptr);
    if (!kd) return vec;
    if ((proc_info = kvm_getprocs(kd, KERN_PROC_PID, proc_id, &cntp))) {
      char **cmd = kvm_getargv(kd, proc_info, 0);
      if (cmd) {
        for (int i = 0; cmd[i]; i++) {
          vec.push_back(cmd[i]);
        }
      }
    }
    kvm_close(kd);
    #elif defined(__NetBSD__)
    int cntp = 0;
    kvm_t *kd = nullptr;
    kinfo_proc2 *proc_info = nullptr;
    kd = kvm_openfiles(nullptr, nullptr, nullptr, KVM_NO_FILES, nullptr);
    if (!kd) return vec;
    if ((proc_info = kvm_getproc2(kd, KERN_PROC_PID, proc_id, sizeof(struct kinfo_proc2), &cntp))) {
      char **cmd = kvm_getargv2(kd, proc_info, 0);
      if (cmd) {
        for (int i = 0; cmd[i]; i++) {
          vec.push_back(cmd[i]);
        }
      }
    }
    kvm_close(kd);
    #elif defined(__OpenBSD__)
    int cntp = 0;
    kvm_t *kd = nullptr;
    kinfo_proc *proc_info = nullptr;
    kd = kvm_openfiles(nullptr, nullptr, nullptr, KVM_NO_FILES, nullptr);
    if (!kd) return vec;
    if ((proc_info = kvm_getprocs(kd, KERN_PROC_PID, proc_id, sizeof(struct kinfo_proc), &cntp))) {
      char **cmd = kvm_getargv(kd, proc_info, 0);
      if (cmd) {
        for (int i = 0; cmd[i]; i++) {
          vec.push_back(cmd[i]);
        }
      }
    }
    kvm_close(kd);
    #endif
    #if (defined(__sun) && defined(__SVR4))
    if (vec.empty()) {
      vec = cmd_env_from_proc_id(proc_id, MEMCMD);
    }
    kvm_t *kd = nullptr;
    char **cmd = nullptr;
    struct proc *proc_info = nullptr;
    struct user *proc_user = nullptr;
    if (!vec.empty()) { 
      goto finish;
    }
    kd = kvm_open(nullptr, nullptr, nullptr, O_RDONLY, nullptr);
    if (!kd) return vec;
    if ((proc_info = kvm_getproc(kd, proc_id))) {
      if ((proc_user = kvm_getu(kd, proc_info))) {
        if (!kvm_getcmd(kd, proc_info, proc_user, &cmd, nullptr)) {
          for (int i = 0; cmd[i]; i++) {
            vec.push_back(cmd[i]);
          }
          free(cmd);
        }
      }
    }
    kvm_close(kd);
    finish:
    #endif
    return vec;
  }

  std::vector<std::string> environ_from_proc_id(proc_id_t proc_id) {
    std::vector<std::string> vec;
    #if (!defined(_WIN32) && !defined(_WIN64))
    if (proc_id < 0) return vec;
    #endif
    #if (defined(_WIN32) || defined(_WIN64))
    HANDLE proc = open_process_with_debug_privilege(proc_id);
    if (!proc) return vec;
    std::vector<wchar_t> buffer = cmd_env_cwd_from_proc(proc, MEMENV);
    int i = 0;
    if (!buffer.empty()) {
      while (buffer[i] != L'\0') {
        message_pump();
        vec.push_back(narrow(&buffer[i]));
        i += (int)(wcslen(&buffer[0] + i) + 1);
      }
    }
    CloseHandle(proc);
    #elif (defined(__APPLE__) && defined(__MACH__))
    vec = cmd_env_from_proc_id(proc_id, MEMENV);
    #elif ((defined(__linux__) || defined(__ANDROID__)) || (defined(__sun) && defined(__SVR4)))
    FILE *file = nullptr;
    std::string procfs_path;
    if (proc_id == proc_id_from_self()) {
      procfs_path = "/proc/self/environ";
    } else {
      procfs_path = std::string("/proc/") + std::to_string(proc_id) + std::string("/environ");
    }
    if ((file = fopen(procfs_path.c_str(), "r"))) {
      char *env = nullptr;
      std::size_t size = 0;
      while (getdelim(&env, &size, 0, file) != -1) {
        vec.push_back(env);
      }
      if (env) free(env);
      fclose(file);
    }
    #elif ((defined(__FreeBSD__) || defined(__FreeBSD_kernel__)) || defined(__DragonFly__))
    int cntp = 0;
    kvm_t *kd = nullptr;
    kinfo_proc *proc_info = nullptr;
    const char *nlistf = "/dev/null";
    const char *memf   = "/dev/null";
    kd = kvm_openfiles(nlistf, memf, nullptr, O_RDONLY, nullptr);
    if (!kd) return vec;
    if ((proc_info = kvm_getprocs(kd, KERN_PROC_PID, proc_id, &cntp))) {
      char **env = kvm_getenvv(kd, proc_info, 0);
      if (env) {
        for (int i = 0; env[i]; i++) {
          vec.push_back(env[i]);
        }
      }
    }
    kvm_close(kd);
    #elif defined(__NetBSD__)
    int cntp = 0;
    kvm_t *kd = nullptr;
    kinfo_proc2 *proc_info = nullptr;
    kd = kvm_openfiles(nullptr, nullptr, nullptr, KVM_NO_FILES, nullptr);
    if (!kd) return vec;
    if ((proc_info = kvm_getproc2(kd, KERN_PROC_PID, proc_id, sizeof(struct kinfo_proc2), &cntp))) {
      char **env = kvm_getenvv2(kd, proc_info, 0);
      if (env) {
        for (int i = 0; env[i]; i++) {
          vec.push_back(env[i]);
        }
      }
    }
    kvm_close(kd);
    #elif defined(__OpenBSD__)
    int cntp = 0;
    kvm_t *kd = nullptr;
    kinfo_proc *proc_info = nullptr;
    kd = kvm_openfiles(nullptr, nullptr, nullptr, KVM_NO_FILES, nullptr);
    if (!kd) return vec;
    if ((proc_info = kvm_getprocs(kd, KERN_PROC_PID, proc_id, sizeof(struct kinfo_proc), &cntp))) {
      char **env = kvm_getenvv(kd, proc_info, 0);
      if (env) {
        for (int i = 0; env[i]; i++) {
          vec.push_back(env[i]);
        }
      }
    }
    kvm_close(kd);
    #endif
    #if (defined(__sun) && defined(__SVR4))
    if (vec.empty()) {
      vec = cmd_env_from_proc_id(proc_id, MEMENV);
    }
    kvm_t *kd = nullptr;
    char **env = nullptr;
    struct proc *proc_info = nullptr;
    struct user *proc_user = nullptr;
    if (!vec.empty()) { 
      goto finish;
    }
    kd = kvm_open(nullptr, nullptr, nullptr, O_RDONLY, nullptr);
    if (!kd) return vec;
    if ((proc_info = kvm_getproc(kd, proc_id))) {
      if ((proc_user = kvm_getu(kd, proc_info))) {
        if (!kvm_getcmd(kd, proc_info, proc_user, nullptr, &env)) {
          for (int i = 0; env[i]; i++) {
            vec.push_back(env[i]);
          }
          free(env);
        }
      }
    }
    kvm_close(kd);
    finish:
    #endif
    struct is_invalid {
      bool operator()(std::string envp) {
        return (envp.find('=') == std::string::npos);
      }
    };
    vec.erase(std::remove_if(vec.begin(), vec.end(), is_invalid()), vec.end());
    return vec;
  }

  std::string envvar_value_from_proc_id(proc_id_t proc_id, std::string name) {
    std::string value;
    #if (!defined(_WIN32) && !defined(_WIN64))
    if (proc_id < 0) return value;
    #endif
    std::vector<std::string> vec = environ_from_proc_id(proc_id);
    if (!vec.empty()) {
      for (std::size_t i = 0; i < vec.size(); i++) {
        message_pump();
        std::vector<std::string> equalssplit = string_split_by_first_equals_sign(vec[i]);
        if (equalssplit.size() == 2) {
          #if (defined(_WIN32) || defined(_WIN64))
          std::transform(equalssplit[0].begin(), equalssplit[0].end(), equalssplit[0].begin(), ::toupper);
          std::transform(name.begin(), name.end(), name.begin(), ::toupper);
          #endif
          if (equalssplit[0] == name) {
            value = equalssplit[1];
            break;
          }
        }
      }
    }
    return value;
  }

  bool envvar_exists_from_proc_id(proc_id_t proc_id, std::string name) {
    bool exists = false;
    #if (!defined(_WIN32) && !defined(_WIN64))
    if (proc_id < 0) return exists;
    #endif
    std::vector<std::string> vec = environ_from_proc_id(proc_id);
    if (!vec.empty()) {
      for (std::size_t i = 0; i < vec.size(); i++) {
        message_pump();
        std::vector<std::string> equalssplit = string_split_by_first_equals_sign(vec[i]);
        if (!equalssplit.empty()) {
          #if (defined(_WIN32) || defined(_WIN64))
          std::transform(equalssplit[0].begin(), equalssplit[0].end(), equalssplit[0].begin(), ::toupper);
          std::transform(name.begin(), name.end(), name.begin(), ::toupper);
          #endif
          if (equalssplit[0] == name) {
            exists = true;
            break;
          }
        }
      }
    }
    return exists;
  }

} // namespace proc_id_info
#endif
