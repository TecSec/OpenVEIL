//	Copyright (c) 2018, TecSec, Inc.
//
//	Redistribution and use in source and binary forms, with or without
//	modification, are permitted provided that the following conditions are met:
//	
//		* Redistributions of source code must retain the above copyright
//		  notice, this list of conditions and the following disclaimer.
//		* Redistributions in binary form must reproduce the above copyright
//		  notice, this list of conditions and the following disclaimer in the
//		  documentation and/or other materials provided with the distribution.
//		* Neither the name of TecSec nor the names of the contributors may be
//		  used to endorse or promote products derived from this software 
//		  without specific prior written permission.
//		 
//	ALTERNATIVELY, provided that this notice is retained in full, this product
//	may be distributed under the terms of the GNU General Public License (GPL),
//	in which case the provisions of the GPL apply INSTEAD OF those given above.
//		 
//	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
//	ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//	WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//	DISCLAIMED.  IN NO EVENT SHALL TECSEC BE LIABLE FOR ANY 
//	DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//	(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
//	LOSS OF USE, DATA OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
//	ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
//	(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
//	SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Written by Roger Butler


#include "stdafx.h"
#ifndef _WIN32
#include <sys/stat.h>
#include <errno.h>
#endif // _WIN32

#ifdef _WIN32
    #undef _WIN32_IE
    #define _WIN32_IE 0x0501
    #include "shlwapi.h"
    #include "shlobj.h"
    static HINSTANCE kernelModule = 0;
#endif

using namespace tscrypto;

#ifndef MIN
#   define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif

void tscrypto::xp_SplitPath(const tsCryptoStringBase &inPath, tsCryptoStringBase &path, tsCryptoStringBase &name, tsCryptoStringBase &ext)
{
	tsCryptoString iPath(inPath);

	path.clear();
	name.clear();
	ext.clear();

	if (tsStrrChr(iPath.c_str(), XP_PATH_SEP_CHAR) != 0)
	{
		name = tsStrrChr(iPath.c_str(), XP_PATH_SEP_CHAR) + 1;
		iPath.resize(iPath.size() - name.size());
	}
	else
	{
		name = iPath;
		iPath.clear();
	}

	if (tsStrrChr(name.c_str(), '.') != NULL)
	{
		ext = tsStrrChr(name.c_str(), '.');
		name.resize(name.size() - ext.size());
	}

	// Get the file path
	path = iPath;
}




uint32_t tscrypto::xp_GetLastError()
{
#ifdef _WIN32
    return GetLastError();
#else
    return errno;
#endif
}

// 06/21/2010 KRR changed parameter to DWORD to be consistant with Windows
// should change definition of unit32_t to DWORD anyway
//HIDDEN void     xp_SetLastError(uint32_t setTo)
void tscrypto::xp_SetLastError(uint32_t setTo)
{
#ifdef _WIN32
    SetLastError(setTo);
#else
   errno = setTo;
#endif
}

bool     tscrypto::xp_GetBootDriveRoot(tsCryptoStringBase &path)
{
#ifdef _WIN32
    char localPath[MAX_PATH];
    typedef BOOL (STDMETHODCALLTYPE *fn)(char *path, int pathLen);
    fn Func;

    if ( kernelModule == 0 )
    {
        kernelModule = GetModuleHandleA(("KERNEL32.DLL"));
    }
    if ( kernelModule == 0 )
        return false;
    Func = (fn)GetProcAddress(kernelModule, "GetSystemWindowsDirectoryA");
    if ( Func == 0 )
        return false;
    Func(localPath, sizeof(localPath) / sizeof(localPath[0]));
    if ( localPath[1] == ':' && localPath[2] == XP_PATH_SEP_CHAR )
        localPath[3] = 0;
	path = localPath;
    return true;
#else
    path = XP_PATH_SEP_STR;
    return true;
#endif
}

bool tscrypto::xp_ReadAllText(const tsCryptoStringBase& filename, tsCryptoStringBase& contents)
{
    TSFILE file = NULL;
    int64_t size;

    contents.clear();

    if (tsFOpen(&file, filename.c_str(), "rb", tsShare_DenyNO) != 0)
        return ts_false;

    size = tsGetFileSize64FromHandle(file);
    if (size > 0x7fffffff)
    {
        tsCloseFile(file);
        return ts_false;
    }
    contents.resize((size_t)size);
    if (tsReadFile(contents.rawData(), 1, (uint32_t)size, file) != (size_t)size)
    {
        contents.clear();
        tsCloseFile(file);
        return ts_false;
    }
    tsCloseFile(file);
    return ts_true;
}

bool tscrypto::xp_ReadAllBytes(const tsCryptoStringBase& filename, tsCryptoData& contents)
{
    TSFILE file = NULL;
    int64_t size;

    contents.clear();

    if (tsFOpen(&file, filename.c_str(), "rb", tsShare_DenyNO) != 0)
        return ts_false;

    size = tsGetFileSize64FromHandle(file);
    if (size > 0x7fffffff)
    {
        tsCloseFile(file);
        return ts_false;
    }
    contents.resize((size_t)size);
    if (tsReadFile(contents.rawData(), 1, (uint32_t)size, file) != (size_t)size)
    {
        contents.clear();
        tsCloseFile(file);
        return ts_false;
    }
    tsCloseFile(file);
    return ts_true;
}

bool tscrypto::xp_StringToTextLines(const tsCryptoStringBase& input, tsCryptoStringList& contents)
{
    tsCryptoString text(input);
    size_t count = 0;
    size_t start = 0;
    size_t end = 0;

	if (!contents)
		contents = CreateTsCryptoStringList();
    if (text.size() > 0 && text[text.size() - 1] != '\n' && text[text.size() - 1] != '\r')
        text.append("\n");
    // Find out how many lines there are
    for (int i = 0; i < (int)text.size(); i++)
    {
        if (text[i] == '\r')
        {
            if (text[i + 1] == '\n')
                continue;
            count++;
        }
        else if (text[i] == '\n')
            count++;
    }
    // Presize the list
	contents->clear();
    contents->reserve(count);
    // And now fill the list
    for (end = 0, start = 0; end < text.size(); end++)
    {
        if (text[end] == '\r')
        {
            contents->push_back(tsCryptoString(&text.c_str()[start], end - start));
            if (text[end + 1] == '\n')
                end++;
            start = end + 1;
        }
        else if (text[end] == '\n')
        {
            contents->push_back(tsCryptoString(&text.c_str()[start], end - start));
            start = end + 1;
        }
    }
    return true;
}

bool tscrypto::xp_ReadAllTextLines(const tsCryptoStringBase& filename, tsCryptoStringList& contents)
{
    tsCryptoString text;
    size_t count = 0;
    size_t start = 0;
    size_t end = 0;

	if (!contents)
		contents = CreateTsCryptoStringList();
	if (!xp_ReadAllText(filename, text))
        return false;

    if (text.size() > 0 && text[text.size() - 1] != '\n' && text[text.size() - 1] != '\r')
        text.append("\n");
    // Find out how many lines there are
    for (int i = 0; i < (int)text.size(); i++)
    {
        if (text[i] == '\r')
        {
            if (text[i + 1] == '\n')
                continue;
            count++;
        }
        else if (text[i] == '\n')
            count++;
    }
    // Presize the list
	contents->clear();
	contents->reserve(count);
	// And now fill the list
    for (end = 0, start = 0; end < text.size(); end++)
    {
        if (text[end] == '\r')
        {
			contents->push_back(tsCryptoString(&text.c_str()[start], end - start));
            if (text[end + 1] == '\n')
                end++;
            start = end + 1;
        }
        else if (text[end] == '\n')
        {
			contents->push_back(tsCryptoString(&text.c_str()[start], end - start));
            start = end + 1;
        }
    }
    return true;
}

//#ifdef _WIN32
//HRESULT STDMETHODCALLTYPE XP_StgOpenStorage(const ts_wchar* pwcsName,
//              IXPStorage* pstgPriority,
//              DWORD grfMode,
//              XP_SNB snbExclude,
//              DWORD reserved,
//              IXPStorage** ppstgOpen)
//{
//    return StgOpenStorage(pwcsName, (IStorage*)pstgPriority, grfMode, snbExclude, reserved, (IStorage**)ppstgOpen);
//}
//
//HRESULT STDMETHODCALLTYPE XP_StgCreateDocfile(const ts_wchar* pwcsName,
//            DWORD grfMode,
//            DWORD reserved,
//            IXPStorage** ppstgOpen)
//{
//    return StgCreateDocfile(pwcsName, grfMode, reserved, (IStorage**)ppstgOpen);
//}
//#endif // _WIN32
