@echo off

if "%BASEPATH%"=="" set BASEPATH=%path%
set path=C:\mingw-w64\x86_64-6.2.0-posix-seh-rt_v5-rev1\mingw64\bin;C:\Program Files (x86)\Windows Kits\8.1\bin\x64\;%BASEPATH%
set TS_GCC_THREAD=p
