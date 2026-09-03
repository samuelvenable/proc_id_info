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

#pragma once
#if ((defined(_WIN32) || defined(_WIN64)) || (defined(__APPLE__) && defined(__MACH__)) || (defined(__linux__) || defined(__ANDROID__)) || (defined(__FreeBSD__) || defined(__FreeBSD_kernel__)) || defined(__DragonFly__) || defined(__NetBSD__) || defined(__OpenBSD__) || (defined(__sun) && defined(__SVR4)))
#include <cstdint>
#if (defined(__sun) && defined(__SVR4))
#if (((defined(INTPTR_MAX) && defined(INT64_MAX)) && INTPTR_MAX != INT64_MAX) || (!defined(INTPTR_MAX) || !defined(INT64_MAX)))
#error "Unsupported Platform! Only 64-bit Architectures are Supported on Solaris and illumos."
#endif
#endif
#if (defined(__APPLE__) && defined(__MACH__))
#include <TargetConditionals.h>
#if (!defined(TARGET_OS_OSX) || !TARGET_OS_OSX)
#error "Unsupported Platform! Supported Platforms: Windows, macOS, GNU/Linux, FreeBSD, DragonFly BSD, NetBSD, OpenBSD, Solaris, illumos, and Android."
#endif
#endif
#else
#error "Unsupported Platform! Supported Platforms: Windows, macOS, GNU/Linux, FreeBSD, DragonFly BSD, NetBSD, OpenBSD, Solaris, illumos, and Android."
#endif
#if ((defined(_WIN32) || defined(_WIN64)) || ((defined(__APPLE__) && defined(__MACH__)) && (defined(TARGET_OS_OSX) && TARGET_OS_OSX)) || (defined(__linux__) || defined(__ANDROID__)) || (defined(__FreeBSD__) || defined(__FreeBSD_kernel__)) || defined(__DragonFly__) || defined(__NetBSD__) || defined(__OpenBSD__) || ((defined(__sun) && defined(__SVR4)) && ((defined(INTPTR_MAX) && defined(INT64_MAX)) && (INTPTR_MAX == INT64_MAX))))
#if !defined(__proc_id_info_supported__)
#define __proc_id_info_supported__
#endif
#include <vector>
#include <string>

namespace proc_id_info {

  #if (!defined(_WIN32) && !defined(_WIN64))
  typedef int proc_id_t;
  #else
  typedef unsigned long proc_id_t;
  #endif

  proc_id_t proc_id_from_self();
  std::vector<proc_id_t> proc_id_enum();
  bool proc_id_exists(proc_id_t proc_id);
  bool proc_id_suspend(proc_id_t proc_id);
  bool proc_id_resume(proc_id_t proc_id);
  bool proc_id_kill(proc_id_t proc_id);
  std::vector<proc_id_t> parent_proc_id_from_proc_id(proc_id_t proc_id);
  std::vector<proc_id_t> proc_id_from_parent_proc_id(proc_id_t parent_proc_id);
  std::string exe_from_proc_id(proc_id_t proc_id);
  std::string cwd_from_proc_id(proc_id_t proc_id);
  std::string comm_from_proc_id(proc_id_t proc_id);
  std::vector<std::string> cmdline_from_proc_id(proc_id_t proc_id);
  std::vector<std::string> environ_from_proc_id(proc_id_t proc_id);
  std::string envvar_value_from_proc_id(proc_id_t proc_id, std::string name);
  bool envvar_exists_from_proc_id(proc_id_t proc_id, std::string name);

} // namespace proc_id_info
#endif
