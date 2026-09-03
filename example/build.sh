#!/bin/sh
cd "${0%/*}";
if [ "$OS" = "Windows_NT" ]; then
  g++ main.cpp ../proc_id_info/proc_id_info.cpp -o a.out.exe -I.. -std=c++17 -static-libgcc -static-libstdc++ -static -lntdll -Wl,--subsystem,console; ./a.out.exe;
elif [ `uname -s` = "Darwin" ]; then
  clang++ main.cpp ../proc_id_info/proc_id_info.cpp -o a.out -I.. -std=c++17 -mmacos-version-min=10.13 -arch arm64 -arch x86_64; ./a.out;
elif [ `uname -s` = "Linux" ]; then
  if [ -f "/bin/g++" ]; then
    g++ main.cpp ../proc_id_info/proc_id_info.cpp -o a.out -I.. -std=c++17 -static-libgcc -static-libstdc++ -static; ./a.out;
  else
    clang++ main.cpp ../proc_id_info/proc_id_info.cpp -o a.out -I.. -std=c++17; ./a.out;
  fi;
elif [ `uname -s` = "FreeBSD" ]; then
  clang++ main.cpp ../proc_id_info/proc_id_info.cpp -o a.out -I.. -std=c++17 -lelf -lkvm -lpthread -static; ./a.out;
elif [ `uname -s` = "DragonFly" ]; then
  g++ main.cpp ../proc_id_info/proc_id_info.cpp -o a.out -I.. -std=c++17 -static-libgcc -static-libstdc++ -lkvm -lpthread -static; ./a.out;
elif [ `uname -s` = "NetBSD" ]; then
  g++ main.cpp ../proc_id_info/proc_id_info.cpp -o a.out -I.. -std=c++17 -static-libgcc -static-libstdc++ -lkvm -lpthread -static; ./a.out;
elif [ `uname -s` = "OpenBSD" ]; then
  clang++ main.cpp ../proc_id_info/proc_id_info.cpp -o a.out -I.. -std=c++17 -lkvm -lpthread -static; ./a.out;
elif [ `uname -s` = "SunOS" ]; then
  if [ `uname -o` = "illumos" ]; then
    g++ main.cpp ../proc_id_info/proc_id_info.cpp -o a.out -I.. -std=c++17 -D__illumos__ -static-libgcc -lkvm -lproc; ./a.out;
  else
    g++ main.cpp ../proc_id_info/proc_id_info.cpp -o a.out -I.. -std=c++17 -static-libgcc -lkvm -lproc; ./a.out;
  fi;
fi;
