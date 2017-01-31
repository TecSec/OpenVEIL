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
  if not exist debug-android-x86-19 md debug-android-x86-19
  pushd debug-android-x86-19
  if not exist resetenv.cmd copy ..\resetenv.cmd . & echo call "%VS140COMNTOOLS%\..\..\vc\vcvarsall" x86 >> resetenv.cmd
  call resetenv
  rem -DANDROID_TOOLCHAIN_NAME=x86-clang3.6
  cmake -DCMAKE_TOOLCHAIN_FILE=../../cmakemodules/android.toolchain.cmake -DANDROID_NDK=%ANDROID_NDK_ROOT% -DCMAKE_BUILD_TYPE=Debug -DTS_VS_CONFIG=Debug -DANDROID_NATIVE_API_LEVEL=19 -DANDROID_STL=gnustl_shared -DANDROID_ABI="x86" -DCMAKE_ANDROID_ARCH=x86 ../..
  rem cmake -DTS_VS_CONFIG=Debug -G "Visual Studio 14" ..\..
  popd

echo ============================================================================
  if not exist release-android-x86-19 md release-android-x86-19
  pushd release-android-x86-19
  if not exist resetenv.cmd copy ..\resetenv.cmd . & echo call "%VS140COMNTOOLS%\..\..\vc\vcvarsall" x86 >> resetenv.cmd
  call resetenv
  rem -DANDROID_TOOLCHAIN_NAME=x86-clang3.6
  cmake -DCMAKE_TOOLCHAIN_FILE=../../cmakemodules/android.toolchain.cmake -DANDROID_NDK=%ANDROID_NDK_ROOT% -DCMAKE_BUILD_TYPE=Release -DTS_VS_CONFIG=Release -DANDROID_NATIVE_API_LEVEL=19 -DANDROID_STL=gnustl_shared -DANDROID_ABI="x86" -DCMAKE_ANDROID_ARCH=x86 ../..
  rem cmake -DTS_VS_CONFIG=Release -G "Visual Studio 14" ..\..
  popd

 
 echo ============================================================================
  if not exist debug-android-arm7v-19 md debug-android-arm7v-19
  pushd debug-android-arm7v-19
  if not exist resetenv.cmd copy ..\resetenv.cmd . & echo call "%VS140COMNTOOLS%\..\..\vc\vcvarsall" x86 >> resetenv.cmd
  call resetenv
  rem -DANDROID_TOOLCHAIN_NAME=arm7v-clang3.6
  cmake -DCMAKE_TOOLCHAIN_FILE=../../cmakemodules/android.toolchain.cmake -DANDROID_NDK=%ANDROID_NDK_ROOT% -DCMAKE_BUILD_TYPE=Debug -DTS_VS_CONFIG=Debug -DANDROID_NATIVE_API_LEVEL=19 -DANDROID_STL=gnustl_shared -DANDROID_ABI="armeabi-v7a" -DCMAKE_ANDROID_ARCH=armv7-a ../..
  rem cmake -DTS_VS_CONFIG=Debug -G "Visual Studio 14" ..\..
  popd

 echo ============================================================================
  if not exist release-android-arm7v-19 md release-android-arm7v-19
  pushd release-android-arm7v-19
  if not exist resetenv.cmd copy ..\resetenv.cmd . & echo call "%VS140COMNTOOLS%\..\..\vc\vcvarsall" x86 >> resetenv.cmd
  call resetenv
  rem -DANDROID_TOOLCHAIN_NAME=arm7v-clang3.6
  cmake -DCMAKE_TOOLCHAIN_FILE=../../cmakemodules/android.toolchain.cmake -DANDROID_NDK=%ANDROID_NDK_ROOT% -DCMAKE_BUILD_TYPE=Release -DTS_VS_CONFIG=Release -DANDROID_NATIVE_API_LEVEL=19 -DANDROID_STL=gnustl_shared -DANDROID_ABI="armeabi-v7a" -DCMAKE_ANDROID_ARCH=armv7-a ../..
  rem cmake -DTS_VS_CONFIG=release -G "Visual Studio 14" ..\..
  popd


 
 
 
  
REM echo ============================================================================
  REM if not exist vsdebug-vc12-x64 md vsdebug-vc12-x64
  REM pushd vsdebug-vc12-x64
  REM if not exist resetenv.cmd copy ..\resetenv.cmd . & echo call "%VS120COMNTOOLS%\..\..\vc\vcvarsall" amd64 >> resetenv.cmd
  REM call resetenv
  REM cmake -DTS_VS_CONFIG=Debug -G "Visual Studio 12 Win64" ..\..
  REM popd
  
REM echo ============================================================================
  REM if not exist vsrelease-vc12-x64 md vsrelease-vc12-x64
  REM pushd vsrelease-vc12-x64
  REM if not exist resetenv.cmd copy ..\resetenv.cmd . & echo call "%VS120COMNTOOLS%\..\..\vc\vcvarsall" amd64 >> resetenv.cmd
  REM call resetenv
  REM cmake -DTS_VS_CONFIG=Release -G "Visual Studio 12 Win64" ..\..
  REM popd
  
  
  
  
echo @echo off > buildall-android-19.cmd
echo SETLOCAL ENABLEEXTENSIONS > buildall-android-19.cmd
echo for %%%%i in (debug release) do ( >> buildall-android-19.cmd
echo    for %%%%j in (android) do ( >> buildall-android-19.cmd
echo      for %%%%k in (x86 arm7v) do ( >> buildall-android-19.cmd
echo 		pushd %%%%i-%%%%j-%%%%k-19 >> buildall-android-19.cmd
echo        call resetenv.cmd >> buildall-android-19.cmd
echo 		cmake --build . --target install --config %%%%i >> buildall-android-19.cmd
echo        if errorlevel 1 ( >> buildall-android-19.cmd
echo           popd  >> buildall-android-19.cmd
echo		   goto :eof >> buildall-android-19.cmd
echo		)  >> buildall-android-19.cmd
echo        if not errorlevel 0 ( >> buildall-android-19.cmd
echo           popd  >> buildall-android-19.cmd
echo		   goto :eof >> buildall-android-19.cmd
echo		)  >> buildall-android-19.cmd
echo 		popd >> buildall-android-19.cmd
echo 	 ) >> buildall-android-19.cmd
echo    ) >> buildall-android-19.cmd
echo ) >> buildall-android-19.cmd

REM echo @echo off > buildrelease-vc12.cmd
REM echo SETLOCAL ENABLEEXTENSIONS > buildrelease-vc12.cmd
REM echo for %%%%i in (release) do ( >> buildrelease-vc12.cmd
REM echo    for %%%%j in (vc12) do ( >> buildrelease-vc12.cmd
REM echo      for %%%%k in (x86 x64) do ( >> buildrelease-vc12.cmd
REM echo 		pushd vs%%%%i-%%%%j-%%%%k >> buildrelease-vc12.cmd
REM echo        call resetenv.cmd >> buildrelease-vc12.cmd
REM echo 		cmake --build . --target uninstall --config %%%%i >> buildrelease-vc12.cmd
REM echo 		cmake --build . --clean-first --target install --config %%%%i >> buildrelease-vc12.cmd
REM echo        if errorlevel 1 ( >> buildrelease-vc12.cmd
REM echo           popd  >> buildrelease-vc12.cmd
REM echo		   goto :eof >> buildrelease-vc12.cmd
REM echo		)  >> buildrelease-vc12.cmd
REM echo        if not errorlevel 0 ( >> buildrelease-vc12.cmd
REM echo           popd  >> buildrelease-vc12.cmd
REM echo		   goto :eof >> buildrelease-vc12.cmd
REM echo		)  >> buildrelease-vc12.cmd
REM echo 		popd >> buildrelease-vc12.cmd
REM echo 	 ) >> buildrelease-vc12.cmd
REM echo    ) >> buildrelease-vc12.cmd
REM echo ) >> buildrelease-vc12.cmd

REM echo @echo off > cleanall-vc12.cmd
REM echo SETLOCAL ENABLEEXTENSIONS > cleanall-vc12.cmd
REM echo for %%%%i in (release debug) do ( >> cleanall-vc12.cmd
REM echo    for %%%%j in (vc12) do ( >> cleanall-vc12.cmd
REM echo      for %%%%k in (x86 x64) do ( >> cleanall-vc12.cmd
REM echo 		pushd vs%%%%i-%%%%j-%%%%k >> cleanall-vc12.cmd
REM echo        call resetenv.cmd >> cleanall-vc12.cmd
REM echo 		cmake --build . --target uninstall --config %%%%i >> cleanall-vc12.cmd
REM echo 		cmake --build . --target clean --config %%%%i >> cleanall-vc12.cmd
REM echo 		popd >> cleanall-vc12.cmd
REM echo 	 ) >> cleanall-vc12.cmd
REM echo    ) >> cleanall-vc12.cmd
REM echo ) >> cleanall-vc12.cmd

REM echo @echo off > cleanrelease-vc12.cmd
REM echo SETLOCAL ENABLEEXTENSIONS > cleanrelease-vc12.cmd
REM echo for %%%%i in (release) do ( >> cleanrelease-vc12.cmd
REM echo    for %%%%j in (vc12) do ( >> cleanrelease-vc12.cmd
REM echo      for %%%%k in (x86 x64) do ( >> cleanrelease-vc12.cmd
REM echo 		pushd vs%%%%i-%%%%j-%%%%k >> cleanrelease-vc12.cmd
REM echo        call resetenv.cmd >> cleanrelease-vc12.cmd
REM echo 		cmake --build . --target uninstall --config %%%%i >> cleanrelease-vc12.cmd
REM echo 		cmake --build . --target clean --config %%%%i >> cleanrelease-vc12.cmd
REM echo 		popd >> cleanrelease-vc12.cmd
REM echo 	 ) >> cleanrelease-vc12.cmd
REM echo    ) >> cleanrelease-vc12.cmd
REM echo ) >> cleanrelease-vc12.cmd

popd
