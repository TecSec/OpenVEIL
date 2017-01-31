//	Copyright (c) 2017, TecSec, Inc.
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
#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>

#ifndef ANDROID

using namespace tscrypto;

XP_FileListHandle tscrypto::xp_GetFileListHandle(const tsCryptoStringBase& searchSpec)
{
	tsCryptoStringList list = CreateTsCryptoStringList();

#ifdef _WIN32
    WIN32_FIND_DATAA fd;
    HANDLE hndl;
    tsCryptoString dir, file, ext;

    xp_SplitPath(searchSpec, dir, file, ext);

    hndl = FindFirstFileA(searchSpec.c_str(), &fd);
    if ( hndl == INVALID_HANDLE_VALUE )
    {
        list->clear();
		return list;
    }
    do
    {
        if ( (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 )
        {
            list->push_back(dir + fd.cFileName);
        }
    }
    while (FindNextFileA(hndl, &fd));
    FindClose(hndl);
    return list;

#elif defined(HAVE_GLOB_H)
    glob_t glob_result;
    struct stat s;

    memset(&glob_result, 0, sizeof(glob_t));
    int retVal = glob(searchSpec.c_str(), GLOB_TILDE,nullptr,&glob_result);
    //printf("glob returned: %d   for '%s'\n", retVal, searchSpec.c_str());
    //printf("  %d paths found\n", (int)glob_result.gl_pathc);
    if (retVal == 0)
    {
        for (unsigned int i = 0; i < glob_result.gl_pathc; i++)
        {
            tsCryptoString tmp1;

            memset(&s, 0, sizeof(s));
            xp_GetFullPathName(glob_result.gl_pathv[i], tmp1, nullptr);
            //printf ("  testing path %s\n", tmp1.c_str());            
            if (stat(tmp1.c_str(), &s) == 0 && S_ISREG(s.st_mode))
            {
                //printf ("    added to the list\n");
                list->push_back(tmp1.c_str());
            }
        }
    }
    globfree(&glob_result);
    return list;
#elif defined(HAVE_DIRENT_H)
    struct dirent de, *result = nullptr;
    tsCryptoString dir, filename, ext;

#error Work needed here
    xp_SplitPath(searchSpec, dir, filename, ext);
    filename << ext;
    filename.Replace("\\", "\\\\").Replace("^", "\\^").Replace(".", "\\.").Replace("$", "\\$").Replace("|", "\\|").Replace("(", "\\(")
        .Replace(")", "\\)").Replace("[", "\\[").Replace("]", "\\]").Replace("*", "\\*").Replace("+", "\\+").Replace("?", "\\?")
        .Replace("/", "\\/").Replace("{", "\\{").Replace("}", "\\}");

	dir << filename;
	DIR* handle = opendir(dir.c_str());
	struct dirent* dp;

	if (handle == nullptr)
	{
        list->clear();
		return list;
	}
	do
	{
		dp = readdir(handle);
		if (dp != nullptr)
		{

		}
	} while (dp != nullptr);
	closedir(handle);


	struct dirent {
		uint64_t         d_ino;
		int64_t          d_off;
		unsigned short   d_reclen;
		unsigned char    d_type;
		char             d_name[256];
	};

	typedef struct DIR DIR;

	extern  DIR*             opendir(const char* dirpath);
	extern  DIR*             fdopendir(int fd);
	extern  struct dirent*   readdir(DIR* dirp);
	extern  int              readdir_r(DIR*  dirp, struct dirent* entry, struct dirent** result);
	extern  int              closedir(DIR* dirp);
	extern  void             rewinddir(DIR* dirp);
	extern  int              dirfd(DIR* dirp);
	extern  int              alphasort(const struct dirent** a, const struct dirent** b);
	extern  int              scandir(const char* dir, struct dirent*** namelist,
		int(*filter)(const struct dirent*),
		int(*compar)(const struct dirent**,
			const struct dirent**));

	extern  int              getdents(unsigned int, struct dirent*, unsigned int);





#else



    #error File list searching not implemented on this platform
#endif
}

XP_FileListHandle tscrypto::xp_GetDirListHandle(const tsCryptoStringBase &searchSpec)
{
    tsCryptoStringList list = CreateTsCryptoStringList();

#ifdef _WIN32
    WIN32_FIND_DATAA fd;
    HANDLE hndl;
    tsCryptoString dir, file, ext;

    xp_SplitPath(searchSpec, dir, file, ext);

    hndl = FindFirstFileA(searchSpec.c_str(), &fd);
    if ( hndl == INVALID_HANDLE_VALUE )
    {
        list->clear();
		return list;
    }
    do
    {
        if ( (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 )
        {
            list->push_back(dir + fd.cFileName);
        }
    }
    while (FindNextFileA(hndl, &fd));
    FindClose(hndl);
    return list;
#elif defined(HAVE_GLOB_H)
    glob_t glob_result;
    struct stat s;

    memset(&glob_result, 0, sizeof(glob_t));
    glob(searchSpec.c_str(), GLOB_TILDE,nullptr,&glob_result);
    for (unsigned int i = 0; i < glob_result.gl_pathc; i++)
    {
        memset(&s, 0, sizeof(s));
        if (stat(glob_result.gl_pathv[i], &s) == 0 && S_ISDIR(s.st_mode))
            list->push_back(glob_result.gl_pathv[i]);
    }
    globfree(&glob_result);
    return list;
#elif defined(HAVE_DIRENT_H)
    struct dirent de, *result = nullptr;
    tsCryptoString dir, filename, ext;
#error Work needed here

    xp_SplitPath(searchSpec, dir, filename, ext);
    filename << ext;
    filename.Replace("\\", "\\\\").Replace("^", "\\^").Replace(".", "\\.").Replace("$", "\\$").Replace("|", "\\|").Replace("(", "\\(")
        .Replace(")", "\\)").Replace("[", "\\[").Replace("]", "\\]").Replace("*", "\\*").Replace("+", "\\+").Replace("?", "\\?")
        .Replace("/", "\\/").Replace("{", "\\{").Replace("}", "\\}");

	dir << filename;
	return (XP_FileListHandle)opendir(dir.c_str());
#else
    #error File list searching not implemented on this platform
#endif
}

size_t tscrypto::xp_GetFileCount(XP_FileListHandle list)
{
	if (list == XP_FILELIST_INVALID)
        return 0;
    return list->size();
}

bool tscrypto::xp_GetFileName(XP_FileListHandle list, DWORD index, tsCryptoStringBase &name)
{
	if (list == XP_FILELIST_INVALID)
        return false;

	if (index >= (DWORD)list->size())
        return false;

	tsCryptoString &str = list->at(index);
	name = str;
    return true;
}

void tscrypto::xp_CloseFileList(XP_FileListHandle list)
{
	if (list == XP_FILELIST_INVALID)
        return;

}
#endif // ANDROID
