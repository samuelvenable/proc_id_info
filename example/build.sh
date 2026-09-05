#!/bin/sh
cd "${0%/*}";
if [ "$OS" = "Windows_NT" ]; then
  g++ main.cpp ../proc_id_info/proc_id_info.cpp -o proc_id_info.exe -I.. -std=c++17 -static-libgcc -static-libstdc++ -static -lntdll -Wl,--subsystem,console; ./proc_id_info.exe;
elif [ `uname -s` = "Darwin" ]; then
  clang++ main.cpp ../proc_id_info/proc_id_info.cpp -o proc_id_info -I.. -std=c++17 -mmacos-version-min=10.13 -arch arm64 -arch x86_64; ./proc_id_info;
elif [ `uname -s` = "Linux" ]; then
  if [ -f "/bin/g++" ]; then
    g++ main.cpp ../proc_id_info/proc_id_info.cpp -o proc_id_info -I.. -std=c++17 -static-libgcc -static-libstdc++ -static; ./proc_id_info;
  else
    clang++ main.cpp ../proc_id_info/proc_id_info.cpp -o proc_id_info -I.. -std=c++17; ./proc_id_info;
  fi;
elif [ `uname -s` = "FreeBSD" ]; then
  clang++ main.cpp ../proc_id_info/proc_id_info.cpp -o proc_id_info -I.. -std=c++17 -lelf -lkvm -lpthread -static; ./proc_id_info;
elif [ `uname -s` = "DragonFly" ]; then
  g++ main.cpp ../proc_id_info/proc_id_info.cpp -o proc_id_info -I.. -std=c++17 -static-libgcc -lkvm -lpthread -static; ./proc_id_info;
elif [ `uname -s` = "NetBSD" ]; then
  g++ main.cpp ../proc_id_info/proc_id_info.cpp -o proc_id_info -I.. -std=c++17 -static-libgcc -lkvm -lpthread -static; ./proc_id_info;
elif [ `uname -s` = "OpenBSD" ]; then
  clang++ main.cpp ../proc_id_info/proc_id_info.cpp -o proc_id_info -I.. -std=c++17 -lkvm -lpthread -static; ./proc_id_info;
elif [ `uname -s` = "SunOS" ]; then
  if [ `uname -o` = "illumos" ]; then
    g++ main.cpp ../proc_id_info/proc_id_info.cpp -o proc_id_info -I.. -std=c++17 -D__illumos__ -static-libgcc -lkvm -lproc; ./proc_id_info;
  else
    g++ main.cpp ../proc_id_info/proc_id_info.cpp -o proc_id_info -I.. -std=c++17 -static-libgcc -lkvm -lproc; ./proc_id_info;
  fi;
fi;
