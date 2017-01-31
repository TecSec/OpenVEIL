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

if not exist ..\..\Build md ..\..\Build
if exist ..\..\Build\resetenv.cmd goto okToBootstrap
copy resetenv.cmd.in ..\..\Build\resetenv.cmd.in
copy resetenv.cmd.in ..\..\Build\resetenv.cmd
echo The resetenv.cmd file has not been customized for your development machine.  Please go to the build folder and rename resetenv.cmd.in to resetenv.cmd and update it for your environment.
echo.

:okToBootstrap

pushd ..\..\Build

echo ============================================================================
  if not exist android-x86-debug md android-x86-debug
  pushd android-x86-debug
  cmake -DCMAKE_TOOLCHAIN_FILE=../../cmakemodules/android.toolchain.cmake -DANDROID_NDK="C:\ProgramData\Microsoft\AndroidNDK\android-ndk-r10e" -DCMAKE_BUILD_TYPE=Debug -DANDROID_ABI="x86" ../..
  rem cmake -DTS_VS_CONFIG=Debug -G "Visual Studio 14" ..\..
  popd

REM echo ============================================================================
  REM if not exist vsrelease-vc14-x86 md vsrelease-vc14-x86
  REM pushd vsrelease-vc14-x86
  REM if not exist resetenv.cmd copy ..\resetenv.cmd . & echo call "%VS140COMNTOOLS%\..\..\vc\vcvarsall" x86 >> resetenv.cmd
  REM call resetenv
  REM cmake -DTS_VS_CONFIG=Release -G "Visual Studio 14" ..\..
  REM popd

 
  
REM echo ============================================================================
  REM if not exist vsdebug-vc14-x64 md vsdebug-vc14-x64
  REM pushd vsdebug-vc14-x64
  REM if not exist resetenv.cmd copy ..\resetenv.cmd . & echo call "%VS140COMNTOOLS%\..\..\vc\vcvarsall" amd64 >> resetenv.cmd
  REM call resetenv
  REM cmake -DTS_VS_CONFIG=Debug -G "Visual Studio 14 Win64" ..\..
  REM popd
  
REM echo ============================================================================
  REM if not exist vsrelease-vc14-x64 md vsrelease-vc14-x64
  REM pushd vsrelease-vc14-x64
  REM if not exist resetenv.cmd copy ..\resetenv.cmd . & echo call "%VS140COMNTOOLS%\..\..\vc\vcvarsall" amd64 >> resetenv.cmd
  REM call resetenv
  REM cmake -DTS_VS_CONFIG=Release -G "Visual Studio 14 Win64" ..\..
  REM popd
  
  
REM echo @echo off > buildall-vc14.cmd
REM echo SETLOCAL ENABLEEXTENSIONS > buildall-vc14.cmd
REM echo for %%%%i in (debug release) do ( >> buildall-vc14.cmd
REM echo    for %%%%j in (vc14) do ( >> buildall-vc14.cmd
REM echo      for %%%%k in (x86 x64) do ( >> buildall-vc14.cmd
REM echo 		pushd vs%%%%i-%%%%j-%%%%k >> buildall-vc14.cmd
REM echo        call resetenv.cmd >> buildall-vc14.cmd
REM echo 		cmake --build . --target install --config %%%%i >> buildall-vc14.cmd
REM echo        if errorlevel 1 ( >> buildall-vc14.cmd
REM echo           popd  >> buildall-vc14.cmd
REM echo		   goto :eof >> buildall-vc14.cmd
REM echo		)  >> buildall-vc14.cmd
REM echo        if not errorlevel 0 ( >> buildall-vc14.cmd
REM echo           popd  >> buildall-vc14.cmd
REM echo		   goto :eof >> buildall-vc14.cmd
REM echo		)  >> buildall-vc14.cmd
REM echo 		popd >> buildall-vc14.cmd
REM echo 	 ) >> buildall-vc14.cmd
REM echo    ) >> buildall-vc14.cmd
REM echo ) >> buildall-vc14.cmd

REM echo @echo off > buildrelease-vc14.cmd
REM echo SETLOCAL ENABLEEXTENSIONS > buildrelease-vc14.cmd
REM echo for %%%%i in (release) do ( >> buildrelease-vc14.cmd
REM echo    for %%%%j in (vc14) do ( >> buildrelease-vc14.cmd
REM echo      for %%%%k in (x86 x64) do ( >> buildrelease-vc14.cmd
REM echo 		pushd vs%%%%i-%%%%j-%%%%k >> buildrelease-vc14.cmd
REM echo        call resetenv.cmd >> buildrelease-vc14.cmd
REM echo 		cmake --build . --target uninstall --config %%%%i >> buildrelease-vc14.cmd
REM echo 		cmake --build . --clean-first --target install --config %%%%i >> buildrelease-vc14.cmd
REM echo        if errorlevel 1 ( >> buildrelease-vc14.cmd
REM echo           popd  >> buildrelease-vc14.cmd
REM echo		   goto :eof >> buildrelease-vc14.cmd
REM echo		)  >> buildrelease-vc14.cmd
REM echo        if not errorlevel 0 ( >> buildrelease-vc14.cmd
REM echo           popd  >> buildrelease-vc14.cmd
REM echo		   goto :eof >> buildrelease-vc14.cmd
REM echo		)  >> buildrelease-vc14.cmd
REM echo 		popd >> buildrelease-vc14.cmd
REM echo 	 ) >> buildrelease-vc14.cmd
REM echo    ) >> buildrelease-vc14.cmd
REM echo ) >> buildrelease-vc14.cmd

REM echo @echo off > cleanall-vc14.cmd
REM echo SETLOCAL ENABLEEXTENSIONS > cleanall-vc14.cmd
REM echo for %%%%i in (release debug) do ( >> cleanall-vc14.cmd
REM echo    for %%%%j in (vc14) do ( >> cleanall-vc14.cmd
REM echo      for %%%%k in (x86 x64) do ( >> cleanall-vc14.cmd
REM echo 		pushd vs%%%%i-%%%%j-%%%%k >> cleanall-vc14.cmd
REM echo        call resetenv.cmd >> cleanall-vc14.cmd
REM echo 		cmake --build . --target uninstall --config %%%%i >> cleanall-vc14.cmd
REM echo 		cmake --build . --target clean --config %%%%i >> cleanall-vc14.cmd
REM echo 		popd >> cleanall-vc14.cmd
REM echo 	 ) >> cleanall-vc14.cmd
REM echo    ) >> cleanall-vc14.cmd
REM echo ) >> cleanall-vc14.cmd

REM echo @echo off > cleanrelease-vc14.cmd
REM echo SETLOCAL ENABLEEXTENSIONS > cleanrelease-vc14.cmd
REM echo for %%%%i in (release) do ( >> cleanrelease-vc14.cmd
REM echo    for %%%%j in (vc14) do ( >> cleanrelease-vc14.cmd
REM echo      for %%%%k in (x86 x64) do ( >> cleanrelease-vc14.cmd
REM echo 		pushd vs%%%%i-%%%%j-%%%%k >> cleanrelease-vc14.cmd
REM echo        call resetenv.cmd >> cleanrelease-vc14.cmd
REM echo 		cmake --build . --target uninstall --config %%%%i >> cleanrelease-vc14.cmd
REM echo 		cmake --build . --target clean --config %%%%i >> cleanrelease-vc14.cmd
REM echo 		popd >> cleanrelease-vc14.cmd
REM echo 	 ) >> cleanrelease-vc14.cmd
REM echo    ) >> cleanrelease-vc14.cmd
REM echo ) >> cleanrelease-vc14.cmd

popd
