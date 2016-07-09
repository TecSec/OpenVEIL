@echo off

if "%BASEPATH%"=="" set BASEPATH=%path%
set path=C:\mingw-w64\x86_64-5.3.0-posix-seh-rt_v4-rev0\mingw64\bin;C:\Program Files (x86)\Windows Kits\8.1\bin\x64\;%BASEPATH%
set TS_GCC_THREAD=p
