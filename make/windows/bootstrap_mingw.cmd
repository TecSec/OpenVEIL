@echo off
rem	Copyright (c) 2017, TecSec, Inc.
rem
rem	Redistribution and use in source and binary forms, with or without
rem	modification, are permitted provided that the following conditions are met:
rem	
rem		* Redistributions of source code must retain the above copyright
rem		  notice, this list of conditions and the following disclaimer.
rem		* Redistributions in binary form must reproduce the above copyright
rem		  notice, this list of conditions and the following disclaimer in the
rem		  documentation and/or other materials provided with the distribution.
rem		* Neither the name of TecSec nor the names of the contributors may be
rem		  used to endorse or promote products derived from this software 
rem		  without specific prior written permission.
rem		 
rem	ALTERNATIVELY, provided that this notice is retained in full, this product
rem	may be distributed under the terms of the GNU General Public License (GPL),
rem	in which case the provisions of the GPL apply INSTEAD OF those given above.
rem		 
rem	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
rem	ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
rem	WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
rem	DISCLAIMED.  IN NO EVENT SHALL TECSEC BE LIABLE FOR ANY 
rem	DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
rem	(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
rem	LOSS OF USE, DATA OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
rem	ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
rem	(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
rem	SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
rem
rem Written by Roger Butler

set COMPILERVERSION=%1
set PROCESSOR=%2

if "%COMPILERVERSION%"=="" set COMPILERVERSION=4.8.2
if "%PROCESSOR%"=="" set PROCESSOR=X64
if "%PROCESSOR%"=="x64" set PROCESSOR=X64
if "%PROCESSOR%"=="x86" set PROCESSOR=X86

if not exist ..\..\Build md ..\..\Build

pushd ..\..\Build

echo ============================================================================
  if not exist release-mingw-%PROCESSOR%-%COMPILERVERSION% md release-mingw-%PROCESSOR%-%COMPILERVERSION%
  pushd release-mingw-%PROCESSOR%-%COMPILERVERSION%
  echo call usegcc%COMPILERVERSION% > resetenv.cmd
  call resetenv
  cmake -DTS_VS_CONFIG=Release -DCMAKE_BUILD_TYPE=Release -DFORCE_%PROCESSOR%=1 -G "Unix Makefiles" ..\..
  echo @echo off > build.cmd
  echo call resetenv >> build.cmd
  echo call cmake --build . -- -j8 >> build.cmd
  echo @echo off > install.cmd
  echo call resetenv >> install.cmd
  echo call cmake --build . --target install -- -j8 >> install.cmd
  echo @echo off > clean.cmd
  echo call resetenv >> clean.cmd
  echo call cmake --build . -- -j8 clean >> clean.cmd
  popd

echo ============================================================================
  if not exist debug-mingw-%PROCESSOR%-%COMPILERVERSION% md debug-mingw-%PROCESSOR%-%COMPILERVERSION%
  pushd debug-mingw-%PROCESSOR%-%COMPILERVERSION%
  echo call usegcc%COMPILERVERSION% > resetenv.cmd
  call resetenv
  cmake -DTS_VS_CONFIG=Debug -DCMAKE_BUILD_TYPE=Debug -DFORCE_%PROCESSOR%=1 -G "Unix Makefiles" ..\..
  echo @echo off > build.cmd
  echo call resetenv >> build.cmd
  echo call cmake --build . -- -j8 >> build.cmd
  echo @echo off > install.cmd
  echo call resetenv >> install.cmd
  echo call cmake --build . --target install -- -j8 >> install.cmd
  echo @echo off > clean.cmd
  echo call resetenv >> clean.cmd
  echo call cmake --build . -- -j8 clean >> clean.cmd
  popd
  
 
echo @echo off > buildall-mingw-%PROCESSOR%-%COMPILERVERSION%.cmd
echo SETLOCAL ENABLEEXTENSIONS > buildall-mingw-%PROCESSOR%-%COMPILERVERSION%.cmd
echo for %%%%i in (debug release) do ( >> buildall-mingw-%PROCESSOR%-%COMPILERVERSION%.cmd
echo    for %%%%j in (mingw) do ( >> buildall-mingw-%PROCESSOR%-%COMPILERVERSION%.cmd
echo      for %%%%k in (%PROCESSOR%) do ( >> buildall-mingw-%PROCESSOR%-%COMPILERVERSION%.cmd
echo 		pushd %%%%i-%%%%j-%%%%k-%COMPILERVERSION% >> buildall-mingw-%PROCESSOR%-%COMPILERVERSION%.cmd
echo        call install.cmd >> buildall-mingw-%PROCESSOR%-%COMPILERVERSION%.cmd
echo        if errorlevel 1 ( >> buildall-mingw-%PROCESSOR%-%COMPILERVERSION%.cmd
echo           popd  >> buildall-mingw-%PROCESSOR%-%COMPILERVERSION%.cmd
echo		   goto :eof >> buildall-mingw-%PROCESSOR%-%COMPILERVERSION%.cmd
echo		)  >> buildall-mingw-%PROCESSOR%-%COMPILERVERSION%.cmd
echo        if not errorlevel 0 ( >> buildall-mingw-%PROCESSOR%-%COMPILERVERSION%.cmd
echo           popd  >> buildall-mingw-%PROCESSOR%-%COMPILERVERSION%.cmd
echo		   goto :eof >> buildall-mingw-%PROCESSOR%-%COMPILERVERSION%.cmd
echo		)  >> buildall-mingw-%PROCESSOR%-%COMPILERVERSION%.cmd
echo 		popd >> buildall-mingw-%PROCESSOR%-%COMPILERVERSION%.cmd
echo 	 ) >> buildall-mingw-%PROCESSOR%-%COMPILERVERSION%.cmd
echo    ) >> buildall-mingw-%PROCESSOR%-%COMPILERVERSION%.cmd
echo ) >> buildall-mingw-%PROCESSOR%-%COMPILERVERSION%.cmd
  
echo @echo off > buildrelease-mingw-%PROCESSOR%-%COMPILERVERSION%.cmd
echo SETLOCAL ENABLEEXTENSIONS > buildrelease-mingw-%PROCESSOR%-%COMPILERVERSION%.cmd
echo for %%%%i in (release) do ( >> buildrelease-mingw-%PROCESSOR%-%COMPILERVERSION%.cmd
echo    for %%%%j in (mingw) do ( >> buildrelease-mingw-%PROCESSOR%-%COMPILERVERSION%.cmd
echo      for %%%%k in (%PROCESSOR%) do ( >> buildrelease-mingw-%PROCESSOR%-%COMPILERVERSION%.cmd
echo 		pushd %%%%i-%%%%j-%%%%k-%COMPILERVERSION% >> buildrelease-mingw-%PROCESSOR%-%COMPILERVERSION%.cmd
echo        call install.cmd >> buildrelease-mingw-%PROCESSOR%-%COMPILERVERSION%.cmd
echo        if errorlevel 1 ( >> buildrelease-mingw-%PROCESSOR%-%COMPILERVERSION%.cmd
echo           popd  >> buildrelease-mingw-%PROCESSOR%-%COMPILERVERSION%.cmd
echo		   goto :eof >> buildrelease-mingw-%PROCESSOR%-%COMPILERVERSION%.cmd
echo		)  >> buildrelease-mingw-%PROCESSOR%-%COMPILERVERSION%.cmd
echo        if not errorlevel 0 ( >> buildrelease-mingw-%PROCESSOR%-%COMPILERVERSION%.cmd
echo           popd  >> buildrelease-mingw-%PROCESSOR%-%COMPILERVERSION%.cmd
echo		   goto :eof >> buildrelease-mingw-%PROCESSOR%-%COMPILERVERSION%.cmd
echo		)  >> buildrelease-mingw-%PROCESSOR%-%COMPILERVERSION%.cmd
echo 		popd >> buildrelease-mingw-%PROCESSOR%-%COMPILERVERSION%.cmd
echo 	 ) >> buildrelease-mingw-%PROCESSOR%-%COMPILERVERSION%.cmd
echo    ) >> buildrelease-mingw-%PROCESSOR%-%COMPILERVERSION%.cmd
echo ) >> buildrelease-mingw-%PROCESSOR%-%COMPILERVERSION%.cmd

REM echo SETLOCAL ENABLEEXTENSIONS > buildrelease.cmd
REM echo    for %%%%j in (vc12) do ( >> buildrelease.cmd
REM echo      for %%%%k in (x86 x64) do ( >> buildrelease.cmd
REM echo 		pushd release-%%%%j-%%%%k >> buildrelease.cmd
REM echo 		call resetenv >> buildrelease.cmd
REM echo 		nmake install >> buildrelease.cmd
REM echo        if errorlevel 1 ( >> buildrelease.cmd
REM echo           popd  >> buildrelease.cmd
REM echo		   goto :eof >> buildrelease.cmd
REM echo		)  >> buildrelease.cmd
REM echo        if not errorlevel 0 ( >> buildrelease.cmd
REM echo           popd  >> buildrelease.cmd
REM echo		   goto :eof >> buildrelease.cmd
REM echo		)  >> buildrelease.cmd
REM echo 		popd >> buildrelease.cmd
REM echo 	 ) >> buildrelease.cmd
REM echo    ) >> buildrelease.cmd

REM echo SETLOCAL ENABLEEXTENSIONS > builddebug.cmd
REM echo    for %%%%j in (vc12) do ( >> builddebug.cmd
REM echo      for %%%%k in (x86 x64) do ( >> builddebug.cmd
REM echo 		pushd debug-%%%%j-%%%%k >> builddebug.cmd
REM echo 		call resetenv >> builddebug.cmd
REM echo 		nmake install >> builddebug.cmd
REM echo        if errorlevel 1 ( >> builddebug.cmd
REM echo           popd  >> builddebug.cmd
REM echo		   goto :eof >> builddebug.cmd
REM echo		)  >> builddebug.cmd
REM echo        if not errorlevel 0 ( >> builddebug.cmd
REM echo           popd  >> builddebug.cmd
REM echo		   goto :eof >> builddebug.cmd
REM echo		)  >> builddebug.cmd
REM echo 		popd >> builddebug.cmd
REM echo 	 ) >> builddebug.cmd
REM echo    ) >> builddebug.cmd

REM echo SETLOCAL ENABLEEXTENSIONS > jom_buildall.cmd
REM echo for %%%%i in (debug release) do ( >> jom_buildall.cmd
REM echo    for %%%%j in (vc12) do ( >> jom_buildall.cmd
REM echo      for %%%%k in (x86 x64) do ( >> jom_buildall.cmd
REM echo 		pushd %%%%i-%%%%j-%%%%k >> jom_buildall.cmd
REM echo 		call resetenv >> jom_buildall.cmd
REM echo 		jom install >> jom_buildall.cmd
REM echo        if errorlevel 1 ( >> jom_buildall.cmd
REM echo           popd  >> jom_buildall.cmd
REM echo		   goto :eof >> jom_buildall.cmd
REM echo		)  >> jom_buildall.cmd
REM echo        if not errorlevel 0 ( >> jom_buildall.cmd
REM echo           popd  >> jom_buildall.cmd
REM echo		   goto :eof >> jom_buildall.cmd
REM echo		)  >> jom_buildall.cmd
REM echo 		popd >> jom_buildall.cmd
REM echo 	 ) >> jom_buildall.cmd
REM echo    ) >> jom_buildall.cmd
REM echo ) >> jom_buildall.cmd

REM echo SETLOCAL ENABLEEXTENSIONS > jom_buildrelease.cmd
REM echo    for %%%%j in (vc12) do ( >> jom_buildrelease.cmd
REM echo      for %%%%k in (x86 x64) do ( >> jom_buildrelease.cmd
REM echo 		pushd release-%%%%j-%%%%k >> jom_buildrelease.cmd
REM echo 		call resetenv >> jom_buildrelease.cmd
REM echo 		jom install >> jom_buildrelease.cmd
REM echo        if errorlevel 1 ( >> jom_buildrelease.cmd
REM echo           popd  >> jom_buildrelease.cmd
REM echo		   goto :eof >> jom_buildrelease.cmd
REM echo		)  >> jom_buildrelease.cmd
REM echo        if not errorlevel 0 ( >> jom_buildrelease.cmd
REM echo           popd  >> jom_buildrelease.cmd
REM echo		   goto :eof >> jom_buildrelease.cmd
REM echo		)  >> jom_buildrelease.cmd
REM echo 		popd >> jom_buildrelease.cmd
REM echo 	 ) >> jom_buildrelease.cmd
REM echo    ) >> jom_buildrelease.cmd

REM echo SETLOCAL ENABLEEXTENSIONS > jom_builddebug.cmd
REM echo    for %%%%j in (vc12) do ( >> jom_builddebug.cmd
REM echo      for %%%%k in (x86 x64) do ( >> jom_builddebug.cmd
REM echo 		pushd debug-%%%%j-%%%%k >> jom_builddebug.cmd
REM echo 		call resetenv >> jom_builddebug.cmd
REM echo 		jom install >> jom_builddebug.cmd
REM echo        if errorlevel 1 ( >> jom_builddebug.cmd
REM echo           popd  >> jom_builddebug.cmd
REM echo		   goto :eof >> jom_builddebug.cmd
REM echo		)  >> jom_builddebug.cmd
REM echo        if not errorlevel 0 ( >> jom_builddebug.cmd
REM echo           popd  >> jom_builddebug.cmd
REM echo		   goto :eof >> jom_builddebug.cmd
REM echo		)  >> jom_builddebug.cmd
REM echo 		popd >> jom_builddebug.cmd
REM echo 	 ) >> jom_builddebug.cmd
REM echo    ) >> jom_builddebug.cmd

REM echo SETLOCAL ENABLEEXTENSIONS > cleanall.cmd
REM echo for %%%%i in (debug release) do ( >> cleanall.cmd
REM echo    for %%%%j in (vc12) do ( >> cleanall.cmd
REM echo      for %%%%k in (x86 x64) do ( >> cleanall.cmd
REM echo 		pushd %%%%i-%%%%j-%%%%k >> cleanall.cmd
REM echo 		call resetenv >> cleanall.cmd
REM echo 		nmake uninstall >> cleanall.cmd
REM echo 		nmake clean >> cleanall.cmd
REM echo 		popd >> cleanall.cmd
REM echo 	 ) >> cleanall.cmd
REM echo    ) >> cleanall.cmd
REM echo ) >> cleanall.cmd

REM echo SETLOCAL ENABLEEXTENSIONS > cleanrelease.cmd
REM echo    for %%%%j in (vc12) do ( >> cleanrelease.cmd
REM echo      for %%%%k in (x86 x64) do ( >> cleanrelease.cmd
REM echo 		pushd release-%%%%j-%%%%k >> cleanrelease.cmd
REM echo 		call resetenv >> cleanrelease.cmd
REM echo 		nmake uninstall >> cleanrelease.cmd
REM echo 		nmake clean >> cleanrelease.cmd
REM echo 		popd >> cleanrelease.cmd
REM echo 	 ) >> cleanrelease.cmd
REM echo    ) >> cleanrelease.cmd

REM echo SETLOCAL ENABLEEXTENSIONS > cleandebug.cmd
REM echo    for %%%%j in (vc12) do ( >> cleandebug.cmd
REM echo      for %%%%k in (x86 x64) do ( >> cleandebug.cmd
REM echo 		pushd debug-%%%%j-%%%%k >> cleandebug.cmd
REM echo 		call resetenv >> cleandebug.cmd
REM echo 		nmake uninstall >> cleandebug.cmd
REM echo 		nmake clean >> cleandebug.cmd
REM echo 		popd >> cleandebug.cmd
REM echo 	 ) >> cleandebug.cmd
REM echo    ) >> cleandebug.cmd

REM echo SETLOCAL ENABLEEXTENSIONS > installall.cmd
REM echo for %%%%i in (debug release) do ( >> installall.cmd
REM echo    for %%%%j in (vc12) do ( >> installall.cmd
REM echo      for %%%%k in (x86 x64) do ( >> installall.cmd
REM echo 		pushd %%%%i-%%%%j-%%%%k >> installall.cmd
REM echo 		call resetenv >> installall.cmd
REM echo 		nmake install >> installall.cmd
REM echo        if errorlevel 1 ( >> installall.cmd
REM echo           popd  >> installall.cmd
REM echo		   goto :eof >> installall.cmd
REM echo		)  >> installall.cmd
REM echo        if not errorlevel 0 ( >> installall.cmd
REM echo           popd  >> installall.cmd
REM echo		   goto :eof >> installall.cmd
REM echo		)  >> installall.cmd
REM echo 		popd >> installall.cmd
REM echo 	 ) >> installall.cmd
REM echo    ) >> installall.cmd
REM echo ) >> installall.cmd

REM echo SETLOCAL ENABLEEXTENSIONS > installrelease.cmd
REM echo    for %%%%j in (vc12) do ( >> installrelease.cmd
REM echo      for %%%%k in (x86 x64) do ( >> installrelease.cmd
REM echo 		pushd release-%%%%j-%%%%k >> installrelease.cmd
REM echo 		call resetenv >> installrelease.cmd
REM echo 		nmake install >> installrelease.cmd
REM echo        if errorlevel 1 ( >> installrelease.cmd
REM echo           popd  >> installrelease.cmd
REM echo		   goto :eof >> installrelease.cmd
REM echo		)  >> installrelease.cmd
REM echo        if not errorlevel 0 ( >> installrelease.cmd
REM echo           popd  >> installrelease.cmd
REM echo		   goto :eof >> installrelease.cmd
REM echo		)  >> installrelease.cmd
REM echo 		popd >> installrelease.cmd
REM echo 	 ) >> installrelease.cmd
REM echo    ) >> installrelease.cmd

REM echo SETLOCAL ENABLEEXTENSIONS > installdebug.cmd
REM echo    for %%%%j in (vc12) do ( >> installdebug.cmd
REM echo      for %%%%k in (x86 x64) do ( >> installdebug.cmd
REM echo 		pushd debug-%%%%j-%%%%k >> installdebug.cmd
REM echo 		call resetenv >> installdebug.cmd
REM echo 		nmake install >> installdebug.cmd
REM echo        if errorlevel 1 ( >> installdebug.cmd
REM echo           popd  >> installdebug.cmd
REM echo		   goto :eof >> installdebug.cmd
REM echo		)  >> installdebug.cmd
REM echo        if not errorlevel 0 ( >> installdebug.cmd
REM echo           popd  >> installdebug.cmd
REM echo		   goto :eof >> installdebug.cmd
REM echo		)  >> installdebug.cmd
REM echo 		popd >> installdebug.cmd
REM echo 	 ) >> installdebug.cmd
REM echo    ) >> installdebug.cmd

  
REM for %%i in (debug release) do (
  REM for %%j in (vc12) do (
    REM for %%k in (x86 x64) do (
      REM echo @echo off > %%i-%%j-%%k\build.cmd
      REM echo call resetenv >> %%i-%%j-%%k\build.cmd
      REM echo nmake install >> %%i-%%j-%%k\build.cmd

      REM echo @echo off > %%i-%%j-%%k\clean.cmd
      REM echo call resetenv >> %%i-%%j-%%k\clean.cmd
      REM echo nmake uninstall >> %%i-%%j-%%k\clean.cmd
      REM echo nmake clean >> %%i-%%j-%%k\clean.cmd
	  
      REM echo @echo off > %%i-%%j-%%k\jom_build.cmd
      REM echo call resetenv >> %%i-%%j-%%k\jom_build.cmd
      REM echo jom install >> %%i-%%j-%%k\jom_build.cmd
    REM )
  REM )
REM )
  
popd
