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

BOOL     tscrypto::xp_DeleteFile(const tsCryptoStringBase &path)
{
#ifdef _WIN32
	//GUID id;
	//CoCreateGuid(&id);

	//if (!xp_RenameFile(path, path + "." + TSGuidToString(id)))
	//{
	//	DWORD err = GetLastError();

	//	if (err == ERROR_FILE_NOT_FOUND)
	//		return TRUE;
	//	return FALSE;
	//}

	//return DeleteFileA((path + "." + TSGuidToString(id)).c_str());
    return DeleteFileA(path.c_str());
#else
    return (unlink(path.c_str()) == 0);
#endif
}

int64_t  tscrypto::xp_GetFileSize(const tsCryptoStringBase &path)
{
#ifdef _WIN32

	HANDLE file = CreateFileA(path.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE)
		return 0;
	int64_t size;
	if (!GetFileSizeEx(file, (LARGE_INTEGER*)&size))
		size = 0;
	CloseHandle(file);
	return size;
#else
	struct stat st;

	if (stat(path.c_str(), &st) != 0)
		return 0;
	return st.st_size;
#endif
}

BOOL tscrypto::xp_RenameFile(const tsCryptoStringBase &oldName, const tsCryptoStringBase &newName)
{
#ifdef _WIN32
	DWORD dwError = ERROR_SUCCESS;
	BOOL bRetVal = MoveFileExA(oldName.c_str(), newName.c_str(), MOVEFILE_COPY_ALLOWED);
	dwError = GetLastError();

	switch (dwError)
	{
	case ERROR_ACCESS_DENIED:
		errno = EACCES;
		break;
	case ERROR_FILE_NOT_FOUND:
		errno = ENOENT;
		break;
	case ERROR_SUCCESS:
		errno = 0;
		break;
	default:
		errno = EINVAL;
		break;
	}

	return bRetVal;
#else
	return rename(oldName.c_str(), newName.c_str()) == 0;
#endif
}

uint32_t tscrypto::xp_GetFileAttributes(const tsCryptoStringBase &path)
{
#ifdef _WIN32
	return GetFileAttributesA(path.c_str());
#else
	struct stat st;
	uint32_t attrs = 0;

	if (lstat(path.c_str(), &st) != 0)
		return XP_INVALID_FILE_ATTRIBUTES;
	if (S_ISLNK(st.st_mode))
		attrs |= XP_FILE_ATTRIBUTE_REPARSE_POINT;
	if (stat(path.c_str(), &st) != 0)
		return XP_INVALID_FILE_ATTRIBUTES;
	if (S_ISDIR(st.st_mode))
		attrs |= XP_FILE_ATTRIBUTE_DIRECTORY;
	else if (S_ISBLK(st.st_mode) && S_ISREG(st.st_mode))
	{
		attrs |= XP_FILE_ATTRIBUTE_NORMAL;
		if (access(path.c_str(), W_OK) != 0)
			attrs |= XP_FILE_ATTRIBUTE_READONLY;
		if (strncmp(path.c_str(), "/tmp/", 5) == 0)
			attrs |= XP_FILE_ATTRIBUTE_TEMPORARY;
	}
	else
		attrs |= XP_FILE_ATTRIBUTE_DEVICE;
	return attrs;
#endif
}

#ifndef _WIN32
static void GetHomeDir(char* path)
{
    const char* homeDir = getenv("HOME");
    const char* lName = nullptr;

    if (path == nullptr)
        return;
    *path = 0;
    if (homeDir != nullptr && homeDir[0] != 0)
    {
        strcpy (path, homeDir);
    }
#ifdef HAVE_PWD_H
    else
    {
        tsCryptoString tmp;
        struct passwd pwd;
        struct passwd *result = nullptr;

        tmp.resize(20000);
        memset(&pwd, 0, sizeof(struct passwd));
        lName = getlogin();
#ifdef HAVE_GETPWNAM_R
        if (lName != nullptr)
            getpwnam_r(lName, &pwd, tmp.rawData(), tmp.size(), &result);
		if (lName != nullptr && result != nullptr && pwd.pw_dir != nullptr)
		{
			strcpy(path, pwd.pw_dir);
		}
		else
		{
			strcpy(path, "/root/");
		}
#else
		if (lName != nullptr)
		{
			result = getpwnam(lName);
			if (result != nullptr)
			{
				lName = result->pw_name;
			}
		}
		if (lName != nullptr && result != nullptr && result->pw_dir != nullptr)
		{
			strcpy(path, result->pw_dir);
		}
		else
		{
			strcpy(path, "/root/");
		}
#endif
    }
#endif
    if (path[strlen(path) - 1] != XP_PATH_SEP_CHAR)
        strcat(path, XP_PATH_SEP_STR);
}
#endif // _WIN32
bool tscrypto::xp_GetSpecialFolder(SpecialFolderType type, tsCryptoStringBase &name)
{
    char path[MAX_PATH] = {0, };
//    int len;

#ifdef _WIN32
	switch (type)
	{
	case sft_PublicDataFolder:
		SHGetFolderPathA(NULL, CSIDL_COMMON_DOCUMENTS | CSIDL_FLAG_CREATE, NULL, SHGFP_TYPE_CURRENT, path);
		break;
	case sft_UserDataFolder:
	case sft_DocumentsFolder:
		SHGetFolderPathA(NULL, CSIDL_PERSONAL | CSIDL_FLAG_CREATE, NULL, SHGFP_TYPE_CURRENT, path);
		break;
	case sft_TempFolder:
		GetTempPathA(sizeof(path) / sizeof(path[0]), path);
		break;
	case sft_SystemFolder:
		SHGetFolderPathA(NULL, CSIDL_SYSTEM | CSIDL_FLAG_CREATE, NULL, SHGFP_TYPE_CURRENT, path);
		break;
	case sft_PolicyData:
		SHGetFolderPathA(NULL, CSIDL_SYSTEM | CSIDL_FLAG_CREATE, NULL, SHGFP_TYPE_CURRENT, path);
		if (path[TsStrLen(path) - 1] != XP_PATH_SEP_CHAR)
		{
			TsStrCat(path, sizeof(path) / sizeof(path[0]), XP_PATH_SEP_STR);
		}
		TsStrCat(path, sizeof(path) / sizeof(path[0]), "GroupPolicy" XP_PATH_SEP_STR "Machine" XP_PATH_SEP_STR "TecSec");
		break;
	case sft_PolicyCkmFavorites:
		SHGetFolderPathA(NULL, CSIDL_SYSTEM | CSIDL_FLAG_CREATE, NULL, SHGFP_TYPE_CURRENT, path);
		if (path[TsStrLen(path) - 1] != XP_PATH_SEP_CHAR)
		{
			TsStrCat(path, sizeof(path) / sizeof(path[0]), XP_PATH_SEP_STR);
		}
		TsStrCat(path, sizeof(path) / sizeof(path[0]), "GroupPolicy" XP_PATH_SEP_STR "Machine" XP_PATH_SEP_STR "TecSec" XP_PATH_SEP_STR "CKM Favorites");
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		break;
	case sft_PolicyDataUser:
		SHGetFolderPathA(NULL, CSIDL_SYSTEM | CSIDL_FLAG_CREATE, NULL, SHGFP_TYPE_CURRENT, path);
		if (path[TsStrLen(path) - 1] != XP_PATH_SEP_CHAR)
		{
			TsStrCat(path, sizeof(path) / sizeof(path[0]), XP_PATH_SEP_STR);
		}
		TsStrCat(path, sizeof(path) / sizeof(path[0]), "GroupPolicy" XP_PATH_SEP_STR "User" XP_PATH_SEP_STR "TecSec");
		break;
	case sft_PolicyUserCkmFavorites:
		SHGetFolderPathA(NULL, CSIDL_SYSTEM | CSIDL_FLAG_CREATE, NULL, SHGFP_TYPE_CURRENT, path);
		if (path[TsStrLen(path) - 1] != XP_PATH_SEP_CHAR)
		{
			TsStrCat(path, sizeof(path) / sizeof(path[0]), XP_PATH_SEP_STR);
		}
		TsStrCat(path, sizeof(path) / sizeof(path[0]), "GroupPolicy" XP_PATH_SEP_STR "User" XP_PATH_SEP_STR "TecSec" XP_PATH_SEP_STR "CKM Favorites");
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		break;
	case sft_WindowsFolder:
		SHGetFolderPathA(NULL, CSIDL_WINDOWS | CSIDL_FLAG_CREATE, NULL, SHGFP_TYPE_CURRENT, path);
		break;
	case sft_ApplicationData:
		SHGetFolderPathA(NULL, CSIDL_APPDATA | CSIDL_FLAG_CREATE, NULL, SHGFP_TYPE_CURRENT, path);
		if (path[TsStrLen(path) - 1] != XP_PATH_SEP_CHAR)
		{
			TsStrCat(path, sizeof(path) / sizeof(path[0]), XP_PATH_SEP_STR);
		}
		TsStrCat(path, sizeof(path) / sizeof(path[0]), "TecSec");
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, TRUE);
		}
		break;
	case sft_CommonApplicationData:
		SHGetFolderPathA(NULL, CSIDL_COMMON_APPDATA | CSIDL_FLAG_CREATE, NULL, SHGFP_TYPE_CURRENT, path);
		if (path[TsStrLen(path) - 1] != XP_PATH_SEP_CHAR)
		{
			TsStrCat(path, sizeof(path) / sizeof(path[0]), XP_PATH_SEP_STR);
		}
		TsStrCat(path, sizeof(path) / sizeof(path[0]), "TecSec");
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, TRUE);
		}
		break;
	case sft_Desktop:
		SHGetFolderPathA(NULL, CSIDL_DESKTOPDIRECTORY | CSIDL_FLAG_CREATE, NULL, SHGFP_TYPE_CURRENT, path);
		break;
	case sft_LocalApplicationData:
		SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA | CSIDL_FLAG_CREATE, NULL, SHGFP_TYPE_CURRENT, path);
		if (path[TsStrLen(path) - 1] != XP_PATH_SEP_CHAR)
		{
			TsStrCat(path, sizeof(path) / sizeof(path[0]), XP_PATH_SEP_STR);
		}
		TsStrCat(path, sizeof(path) / sizeof(path[0]), "TecSec");
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, TRUE);
		}
		break;
	case sft_ProfileFolder:
		SHGetFolderPathA(NULL, CSIDL_PROFILE | CSIDL_FLAG_CREATE, NULL, SHGFP_TYPE_CURRENT, path);
		break;
	case sft_LogFolder:
		SHGetFolderPathA(NULL, CSIDL_WINDOWS | CSIDL_FLAG_CREATE, NULL, SHGFP_TYPE_CURRENT, path);
		if (path[1] == ':')
		{
			path[2] = 0;
			TsStrCat(path, sizeof(path) / sizeof(path[0]), "\\TecSec\\Logs");
		}
		break;
	case sft_TecSecFolder:
		SHGetFolderPathA(NULL, CSIDL_WINDOWS | CSIDL_FLAG_CREATE, NULL, SHGFP_TYPE_CURRENT, path);
		if (path[1] == ':')
		{
			path[2] = 0;
			TsStrCat(path, sizeof(path) / sizeof(path[0]), "\\TecSec");
		}
		break;
	case sft_UserCkmFavorites:
		SHGetFolderPathA(NULL, CSIDL_PERSONAL | CSIDL_FLAG_CREATE, NULL, SHGFP_TYPE_CURRENT, path);
		if (path[TsStrLen(path) - 1] != XP_PATH_SEP_CHAR)
		{
			TsStrCat(path, sizeof(path) / sizeof(path[0]), XP_PATH_SEP_STR);
		}
		TsStrCat(path, sizeof(path) / sizeof(path[0]), "TecSec");
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		TsStrCat(path, sizeof(path) / sizeof(path[0]), XP_PATH_SEP_STR);
		TsStrCat(path, sizeof(path) / sizeof(path[0]), "CKM Favorites");
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, TRUE);
		}
		break;
	case sft_PublicCkmFavorites:
		SHGetFolderPathA(NULL, CSIDL_COMMON_DOCUMENTS | CSIDL_FLAG_CREATE, NULL, SHGFP_TYPE_CURRENT, path);
		if (path[TsStrLen(path) - 1] != XP_PATH_SEP_CHAR)
		{
			TsStrCat(path, sizeof(path) / sizeof(path[0]), XP_PATH_SEP_STR);
		}
		TsStrCat(path, sizeof(path) / sizeof(path[0]), "CKM Favorites");
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		break;
	case sft_SystemCkmFavorites:
		SHGetFolderPathA(NULL, CSIDL_SYSTEM | CSIDL_FLAG_CREATE, NULL, SHGFP_TYPE_CURRENT, path);
		if (path[TsStrLen(path) - 1] != XP_PATH_SEP_CHAR)
		{
			TsStrCat(path, sizeof(path) / sizeof(path[0]), XP_PATH_SEP_STR);
		}
		TsStrCat(path, sizeof(path) / sizeof(path[0]), "CKM Favorites");
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		break;
	case sft_CkmDefaultProgramsPath:
		// KRR 08/04/2011 changed from CSIDL_SYSTEM to CSIDL_PROGRAM_FILES
		SHGetFolderPathA(NULL, CSIDL_PROGRAM_FILES | CSIDL_FLAG_CREATE, NULL, SHGFP_TYPE_CURRENT, path);
		if (path[TsStrLen(path) - 1] != XP_PATH_SEP_CHAR)
		{
			TsStrCat(path, sizeof(path) / sizeof(path[0]), XP_PATH_SEP_STR);
		}
		TsStrCat(path, sizeof(path) / sizeof(path[0]), "TecSec");
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		TsStrCat(path, sizeof(path) / sizeof(path[0]), XP_PATH_SEP_STR);
		TsStrCat(path, sizeof(path) / sizeof(path[0]), "Tools"); // was CKM
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		TsStrCat(path, sizeof(path) / sizeof(path[0]), XP_PATH_SEP_STR);
		break;
	case sft_CommonFiles:
		SHGetFolderPathA(NULL, CSIDL_PROGRAM_FILES_COMMON | CSIDL_FLAG_CREATE, NULL, SHGFP_TYPE_CURRENT, path);
		if (path[TsStrLen(path) - 1] != XP_PATH_SEP_CHAR)
		{
			TsStrCat(path, sizeof(path) / sizeof(path[0]), XP_PATH_SEP_STR);
		}
		TsStrCat(path, sizeof(path) / sizeof(path[0]), "TecSec");
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		TsStrCat(path, sizeof(path) / sizeof(path[0]), XP_PATH_SEP_STR);
		break;
	case sft_BootDriveRoot:
		path[0] = 0;
		path[1] = 0;
		path[2] = 0;
		SHGetFolderPathA(NULL, CSIDL_SYSTEM | CSIDL_FLAG_CREATE, NULL, SHGFP_TYPE_CURRENT, path);
		if (path[1] == ':' && path[2] == XP_PATH_SEP_CHAR)
		{
			path[3] = 0;
		}
		break;
	case sft_UserTokensFolder:
		SHGetFolderPathA(NULL, CSIDL_PERSONAL | CSIDL_FLAG_CREATE, NULL, SHGFP_TYPE_CURRENT, path);
		if (path[TsStrLen(path) - 1] != XP_PATH_SEP_CHAR)
		{
			TsStrCat(path, sizeof(path) / sizeof(path[0]), XP_PATH_SEP_STR);
		}
		TsStrCat(path, sizeof(path) / sizeof(path[0]), "TecSec");
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		TsStrCat(path, sizeof(path) / sizeof(path[0]), XP_PATH_SEP_STR);
		TsStrCat(path, sizeof(path) / sizeof(path[0]), "Tokens");
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, TRUE);
		}
		TsStrCat(path, sizeof(path) / sizeof(path[0]), XP_PATH_SEP_STR);
		break;
	case sft_UserConfigFolder:
		SHGetFolderPathA(NULL, CSIDL_PERSONAL | CSIDL_FLAG_CREATE, NULL, SHGFP_TYPE_CURRENT, path);
		if (path[TsStrLen(path) - 1] != XP_PATH_SEP_CHAR)
		{
			TsStrCat(path, sizeof(path) / sizeof(path[0]), XP_PATH_SEP_STR);
		}
		TsStrCat(path, sizeof(path) / sizeof(path[0]), "TecSec");
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		TsStrCat(path, sizeof(path) / sizeof(path[0]), XP_PATH_SEP_STR);
		break;
	case sft_UserSharesFolder:
		SHGetFolderPathA(NULL, CSIDL_PERSONAL | CSIDL_FLAG_CREATE, NULL, SHGFP_TYPE_CURRENT, path);
		if (path[TsStrLen(path) - 1] != XP_PATH_SEP_CHAR)
		{
			TsStrCat(path, sizeof(path) / sizeof(path[0]), XP_PATH_SEP_STR);
		}
		TsStrCat(path, sizeof(path) / sizeof(path[0]), "TecSec");
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		TsStrCat(path, sizeof(path) / sizeof(path[0]), XP_PATH_SEP_STR);
		TsStrCat(path, sizeof(path) / sizeof(path[0]), "Shares");
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, TRUE);
		}
		TsStrCat(path, sizeof(path) / sizeof(path[0]), XP_PATH_SEP_STR);
		break;
	default:
		return false;
	}
#elif defined(MAC)
	switch (type)
	{
	case sft_BootDriveRoot:         // /
		strcpy(path, "/");
		break;
	case sft_PublicDataFolder:      // /home
		return false; // TODO:  Figure out a path here
	case sft_ProfileFolder:         // /home/asdf
	case sft_UserDataFolder:        // /home/asdf
	case sft_DocumentsFolder:       // /home/asdf
		GetHomeDir(path);
		break;
	case sft_Desktop:               // /home/asdf/Desktop
		GetHomeDir(path);
		strcat(path, "Desktop" XP_PATH_SEP_STR);
		break;
	case sft_UserCkmFavorites:      // /home/asdf/tecsec/.CkmFavorites
		GetHomeDir(path);
		strcat(path, ".tecsec" XP_PATH_SEP_STR);
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		strcat(path, "favorites" XP_PATH_SEP_STR);
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		break;
	case sft_UserTokensFolder:      // /home/asdf/tecsec/.tokens
		GetHomeDir(path);
		strcat(path, ".tecsec" XP_PATH_SEP_STR);
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		strcat(path, "tokens" XP_PATH_SEP_STR);
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		break;
	case sft_UserConfigFolder:      // /home/asdf/tecsec/.config
		GetHomeDir(path);
		strcat(path, ".tecsec" XP_PATH_SEP_STR);
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		strcat(path, "config" XP_PATH_SEP_STR);
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		break;
	case sft_UserSharesFolder:      // /home/asdf/tecsec/.shares
		GetHomeDir(path);
		strcat(path, ".tecsec" XP_PATH_SEP_STR);
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		strcat(path, "shares" XP_PATH_SEP_STR);
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		break;
	case sft_TempFolder:            // /tmp
		strcpy(path, XP_PATH_SEP_STR "tmp" XP_PATH_SEP_STR);
		break;
	case sft_SystemFolder:          // /usr
	case sft_WindowsFolder:         // /usr
		return false;
	case sft_CkmDefaultProgramsPath:// /usr/local/bin
	case sft_CommonFiles:           // /usr/local/bin
		strcpy(path, XP_PATH_SEP_STR "usr" XP_PATH_SEP_STR "local" XP_PATH_SEP_STR "bin" XP_PATH_SEP_STR);
		break;
	case sft_PublicCkmFavorites:    // /private/var/tecsec/favorites
		strcpy(path, XP_PATH_SEP_STR "private" XP_PATH_SEP_STR "var" XP_PATH_SEP_STR "tecsec" XP_PATH_SEP_STR);
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		strcat(path, "favorites" XP_PATH_SEP_STR);
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		break;
	case sft_ApplicationData:       // /private/var/tecsec
	case sft_CommonApplicationData: // /private/var/tecsec
	case sft_LocalApplicationData:  // /private/var/tecsec
		strcpy(path, XP_PATH_SEP_STR "private" XP_PATH_SEP_STR "var" XP_PATH_SEP_STR "tecsec" XP_PATH_SEP_STR);
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		break;
	case sft_LogFolder:             // /private/var/log/tecsec/system
		strcpy(path, XP_PATH_SEP_STR "private" XP_PATH_SEP_STR "var" XP_PATH_SEP_STR "log" XP_PATH_SEP_STR "tecsec" XP_PATH_SEP_STR);
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		break;
	case sft_TecSecFolder:          // /private/var/tecsec/system
		strcpy(path, XP_PATH_SEP_STR "private" XP_PATH_SEP_STR "var" XP_PATH_SEP_STR "tecsec" XP_PATH_SEP_STR "system" XP_PATH_SEP_STR);
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		break;
	case sft_SystemCkmFavorites:    // /var/local/share/tecsec/favorites
		strcpy(path, XP_PATH_SEP_STR "private" XP_PATH_SEP_STR "var" XP_PATH_SEP_STR "tecsec" XP_PATH_SEP_STR "system" XP_PATH_SEP_STR);
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		strcat(path, "favorites" XP_PATH_SEP_STR);
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		break;
	case sft_PolicyData:            // /etc/tecsec/.policy
		strcpy(path, XP_PATH_SEP_STR "etc" XP_PATH_SEP_STR "tecsec" XP_PATH_SEP_STR);
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		strcat(path, "policy" XP_PATH_SEP_STR);
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		break;
	case sft_PolicyDataUser:        // /etc/tecsec/.userpolicy
		strcpy(path, XP_PATH_SEP_STR "etc" XP_PATH_SEP_STR "tecsec" XP_PATH_SEP_STR);
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		strcat(path, "userpolicy" XP_PATH_SEP_STR);
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		break;
	case sft_PolicyCkmFavorites:    // /etc/tecsec/.CkmFavorites
	case sft_PolicyUserCkmFavorites:// /etc/tecsec/.CkmFavorites
		strcpy(path, XP_PATH_SEP_STR "etc" XP_PATH_SEP_STR "tecsec" XP_PATH_SEP_STR);
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		strcat(path, "favorites" XP_PATH_SEP_STR);
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		break;
	default:
		return false;
	}
#else
	switch (type)
	{
	case sft_BootDriveRoot:         // /
		strcpy(path, "/");
		break;
	case sft_PublicDataFolder:      // /home
		return false; // TODO:  Figure out a path here
	case sft_ProfileFolder:         // /home/asdf
	case sft_UserDataFolder:        // /home/asdf
	case sft_DocumentsFolder:       // /home/asdf
		GetHomeDir(path);
		break;
	case sft_Desktop:               // /home/asdf/Desktop
		GetHomeDir(path);
		strcat(path, "Desktop" XP_PATH_SEP_STR);
		break;
	case sft_UserCkmFavorites:      // /home/asdf/tecsec/.CkmFavorites
		GetHomeDir(path);
		strcat(path, ".tecsec" XP_PATH_SEP_STR);
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		strcat(path, "favorites" XP_PATH_SEP_STR);
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		break;
	case sft_UserTokensFolder:      // /home/asdf/tecsec/.tokens
		GetHomeDir(path);
		strcat(path, ".tecsec" XP_PATH_SEP_STR);
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		strcat(path, "tokens" XP_PATH_SEP_STR);
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		break;
	case sft_UserConfigFolder:      // /home/asdf/tecsec/.config
		GetHomeDir(path);
		strcat(path, ".tecsec" XP_PATH_SEP_STR);
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		strcat(path, "config" XP_PATH_SEP_STR);
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		break;
	case sft_UserSharesFolder:      // /home/asdf/tecsec/.shares
		GetHomeDir(path);
		strcat(path, ".tecsec" XP_PATH_SEP_STR);
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		strcat(path, "shares" XP_PATH_SEP_STR);
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		break;
	case sft_TempFolder:            // /tmp
		strcpy(path, XP_PATH_SEP_STR "tmp" XP_PATH_SEP_STR);
		break;
	case sft_SystemFolder:          // /usr
	case sft_WindowsFolder:         // /usr
		return false;
	case sft_CkmDefaultProgramsPath:// /usr/local/bin
	case sft_CommonFiles:           // /usr/local/bin
		strcpy(path, XP_PATH_SEP_STR "usr" XP_PATH_SEP_STR "local" XP_PATH_SEP_STR "bin" XP_PATH_SEP_STR);
		break;
	case sft_PublicCkmFavorites:    // /var/lib/tecsec/.CkmFavorites
		strcpy(path, XP_PATH_SEP_STR "var" XP_PATH_SEP_STR "lib" XP_PATH_SEP_STR "tecsec" XP_PATH_SEP_STR);
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		strcat(path, "favorites" XP_PATH_SEP_STR);
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		break;
	case sft_ApplicationData:       // /var/local/lib/tecsec
	case sft_CommonApplicationData: // /var/local/lib/tecsec
	case sft_LocalApplicationData:  // /var/local/lib/tecsec
		strcpy(path, XP_PATH_SEP_STR "var" XP_PATH_SEP_STR "local" XP_PATH_SEP_STR "lib" XP_PATH_SEP_STR "tecsec" XP_PATH_SEP_STR);
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		break;
	case sft_LogFolder:             // /var/local/log/tecsec
		strcpy(path, XP_PATH_SEP_STR "var" XP_PATH_SEP_STR "log" XP_PATH_SEP_STR "tecsec" XP_PATH_SEP_STR);
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		break;
	case sft_TecSecFolder:          // /var/local/share/tecsec
		strcpy(path, XP_PATH_SEP_STR "var" XP_PATH_SEP_STR "local" XP_PATH_SEP_STR "share" XP_PATH_SEP_STR "tecsec" XP_PATH_SEP_STR);
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		break;
	case sft_SystemCkmFavorites:    // /var/local/share/tecsec/.CkmFavorites
		strcpy(path, XP_PATH_SEP_STR "var" XP_PATH_SEP_STR "local" XP_PATH_SEP_STR "share" XP_PATH_SEP_STR "tecsec" XP_PATH_SEP_STR);
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		strcat(path, "favorites" XP_PATH_SEP_STR);
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		break;
	case sft_PolicyData:            // /etc/tecsec/.policy
		strcpy(path, XP_PATH_SEP_STR "etc" XP_PATH_SEP_STR "tecsec" XP_PATH_SEP_STR);
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		strcat(path, "policy" XP_PATH_SEP_STR);
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		break;
	case sft_PolicyDataUser:        // /etc/tecsec/.userpolicy
		strcpy(path, XP_PATH_SEP_STR "etc" XP_PATH_SEP_STR "tecsec" XP_PATH_SEP_STR);
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		strcat(path, "userpolicy" XP_PATH_SEP_STR);
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		break;
	case sft_PolicyCkmFavorites:    // /etc/tecsec/.CkmFavorites
	case sft_PolicyUserCkmFavorites:// /etc/tecsec/.CkmFavorites
		strcpy(path, XP_PATH_SEP_STR "etc" XP_PATH_SEP_STR "tecsec" XP_PATH_SEP_STR);
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		strcat(path, "favorites" XP_PATH_SEP_STR);
		if (!xp_FileExists(path))
		{
			xp_CreateDirectory(path, FALSE);
		}
		break;
	default:
		return false;
	}
#endif

	if (path[0] != 0 && path[TsStrLen(path) - 1] != XP_PATH_SEP_CHAR)
		TsStrCat(path, sizeof(path) / sizeof(path[0]), XP_PATH_SEP_STR);
	name = path;
	return true;
}

BOOL tscrypto::xp_FileExists(const tsCryptoStringBase &path)
{
#ifdef _WIN32
	return GetFileAttributesA(path.c_str()) != INVALID_FILE_ATTRIBUTES;
#else
	struct stat st;

	if (stat(path.c_str(), &st) != 0)
		return FALSE;
	return TRUE;
#endif
}

bool tscrypto::xp_IsDirectory(const tsCryptoStringBase &path)
{
#ifdef _WIN32
	uint32_t retVal = GetFileAttributesA(path.c_str());
	return (retVal != INVALID_FILE_ATTRIBUTES) && ((retVal & XP_FILE_ATTRIBUTE_DIRECTORY) != 0);
#else
	struct stat st;

	if (stat(path.c_str(), &st) != 0)
		return false;
	if (S_ISDIR(st.st_mode))
		return true;
	return false;
#endif
}

BOOL     tscrypto::xp_CreateDirectory(const tsCryptoStringBase &path, BOOL UserOnly)
{
#ifdef _WIN32
	MY_UNREFERENCED_PARAMETER(UserOnly);
	return CreateDirectoryA(path.c_str(), NULL);
#else
	return (mkdir(path.c_str(), (UserOnly ? 0700 : 0764)) == 0) ? TRUE : FALSE;
#endif
}

void tscrypto::xp_SplitPath(const tsCryptoStringBase &inPath, tsCryptoStringBase &path, tsCryptoStringBase &name, tsCryptoStringBase &ext)
{
	tsCryptoString iPath(inPath);

	path.clear();
	name.clear();
	ext.clear();

	if (TsStrrChr(iPath.c_str(), XP_PATH_SEP_CHAR) != 0)
	{
		name = TsStrrChr(iPath.c_str(), XP_PATH_SEP_CHAR) + 1;
		iPath.resize(iPath.size() - name.size());
	}
	else
	{
		name = iPath;
		iPath.clear();
	}

	if (TsStrrChr(name.c_str(), '.') != NULL)
	{
		ext = TsStrrChr(name.c_str(), '.');
		name.resize(name.size() - ext.size());
	}

	// Get the file path
	path = iPath;
}

BOOL tscrypto::xp_FlushFile(XP_FILE hFile) // TRUE - Flushed, FALSE - Failed
{
    if ( hFile == XP_FILE_INVALID )
        return FALSE;
#ifdef _WIN32
    return FlushFileBuffers((HANDLE)hFile);
#else
    if ( fsync(fileno((FILE*)hFile)) == -1 )
        return FALSE;
    return TRUE;
#endif
}
BOOL tscrypto::xp_TruncateFile(XP_FILE hFile, uint32_t length) // TRUE - truncated, FALSE - Failed
{
    if ( hFile == XP_FILE_INVALID )
        return FALSE;
#ifdef _WIN32
    SetFilePointer((HANDLE)hFile, length, NULL, FILE_BEGIN);
    return SetEndOfFile((HANDLE)hFile);
#else
    if ( ftruncate(fileno((FILE*)hFile), length) == -1 )
        return FALSE;
    return TRUE;
#endif
}

XP_FILE tscrypto::xp_CreateFile(const tsCryptoStringBase &lpFileName,
                     uint32_t dwDesiredAccess,
                     uint32_t dwShareMode,
                     void *lpSecurityAttributes,
                     uint32_t dwCreationDisposition,
                     uint32_t dwFlagsAndAttributes,
                     void *hTemplateFile)
{
#ifdef _WIN32
    HANDLE file = CreateFileA(lpFileName.c_str(), dwDesiredAccess, dwShareMode, (SECURITY_ATTRIBUTES *)lpSecurityAttributes,
                              dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    if ( file == INVALID_HANDLE_VALUE )
        return XP_FILE_INVALID;
    return (XP_FILE)file;
#else
    /***************************************************************
     TODO: Fix this function.  As it is, it does not handle Share Modes correctly
     because of the use of fopen().
    ****************************************************************/

    struct stat stBuf;
    const char *mode = NULL;
    if ((dwDesiredAccess != XP_GENERIC_READ) &&
        (dwDesiredAccess != XP_GENERIC_WRITE) &&
        (dwDesiredAccess != (XP_GENERIC_READ | XP_GENERIC_WRITE)))
    {
        fprintf(stderr, "CreateFile::dwDesiredAccess must be GENERIC_READ, GENERIC_WRITE, or GENERIC_READ | GENERIC_WRITE\n");
        return XP_FILE_INVALID;
    }
/*
    if (dwShareMode != FILE_SHARE_READ && dwShareMode != 0)
    {
        fprintf(stderr, "CreateFile::dwShareMode must be FILE_SHARE_READ or 0\n");
        return INVALID_HANDLE_VALUE;
    }

    if (dwFlagsAndAttributes != FILE_FLAG_RANDOM_ACCESS)
    {
        fprintf(stderr, "CreateFile::dwFlagsAndAttributes must be FILE_FLAG_RANDOM_ACCESS\n");
        return INVALID_HANDLE_VALUE;
    }
*/

    if (NULL != lpSecurityAttributes)
    {
        fprintf(stderr, "lpSecurityAttributes must be NULL\n");
        return XP_FILE_INVALID;
    }

    if (NULL != hTemplateFile)
    {
        fprintf(stderr, "hTemplateFile must be NULL\n");
        return XP_FILE_INVALID;
    }

    if (dwCreationDisposition == XP_CREATE_NEW)
    {
        if (0 == stat(lpFileName.c_str(), &stBuf))
        {
            errno = EEXIST;
             return XP_FILE_INVALID;
        }
    }

    switch (dwDesiredAccess)
    {
        case XP_GENERIC_READ:
           mode = "rb";
           break;
        case XP_GENERIC_WRITE:
           mode = "wb";
           break;
        case XP_GENERIC_READ | XP_GENERIC_WRITE:
            mode = "rb+";
            if (dwCreationDisposition == XP_OPEN_ALWAYS)
            {
                if (0 != stat(lpFileName.c_str(), &stBuf))
                {
                    mode = "wb+";
                }
            }
            else if (dwCreationDisposition == XP_CREATE_NEW)
            {
                if (0 == stat(lpFileName.c_str(), &stBuf))
                {
                    mode = "wb+";
                }
                else
                {
                    errno = EEXIST;
                    return XP_FILE_INVALID;
                }
            }
            else if (dwCreationDisposition == XP_CREATE_ALWAYS)
            {
                mode = "wb+";
            }
            break;
    }

    return (XP_FILE)fopen(lpFileName.c_str(), mode);
#endif
}

BOOL tscrypto::xp_ReadFile(XP_FILE hFile,
                     void * lpBuffer,
                     uint32_t nNumberOfBytesToRead,
                     uint32_t *lpNumberOfBytesRead,
                     void * lpOverlapped)
{
    if ( hFile == XP_FILE_INVALID )
        return FALSE;
#ifdef _WIN32
    return ReadFile((HANDLE)hFile, lpBuffer, nNumberOfBytesToRead, (DWORD*)lpNumberOfBytesRead, (OVERLAPPED*)lpOverlapped);
#else
    *lpNumberOfBytesRead = fread(lpBuffer, 1, nNumberOfBytesToRead, (FILE*)hFile);
    if ((*lpNumberOfBytesRead <= 0) && (nNumberOfBytesToRead != 0))
    {
        return FALSE;
    }
    return TRUE;
#endif
}

BOOL tscrypto::xp_ReadFileLine(XP_FILE hFile,
					 _Out_writes_bytes_(nNumberOfBytesToRead) void * lpBuffer,
                     _In_ uint32_t nNumberOfBytesToRead)
{
    if ( hFile == XP_FILE_INVALID )
        return FALSE;
#ifdef _WIN32
    {
        DWORD position = xp_SetFilePointer(hFile, 0, 0, XP_FILE_CURRENT);
        int64_t length = xp_GetFileSize64FromHandle(hFile);
        DWORD read;
        DWORD origLen = nNumberOfBytesToRead;
        uint32_t i;

        memset(lpBuffer, 0, nNumberOfBytesToRead);
        if ( nNumberOfBytesToRead > length - position )
            nNumberOfBytesToRead = (uint32_t)(length - position);

        if ( !ReadFile((HANDLE)hFile, lpBuffer, nNumberOfBytesToRead, &read, 0) || read == 0)
        {
            return FALSE;
        }
		nNumberOfBytesToRead = origLen;
		read = MIN((uint32_t)read, nNumberOfBytesToRead);
        for (i = 0; i < read; i++)
        {
            if ( ((unsigned char *)lpBuffer)[i] == '\r' )
            {
                if ( i < nNumberOfBytesToRead - 1 )
                {
                    if ( ((unsigned char *)lpBuffer)[i + 1] == '\n' )
                    {
                        i++;
                    }
                }
                if ( i < nNumberOfBytesToRead - 1 )
                {
                    ((unsigned char *)lpBuffer)[i + 1] = 0;
                }
                xp_SetFilePointer(hFile, position + i + 1, 0, XP_FILE_BEGIN);
                return TRUE;
            }
            if ( ((unsigned char *)lpBuffer)[i] == '\n' )
            {
                if ( i < nNumberOfBytesToRead - 1 )
                {
                    ((unsigned char *)lpBuffer)[i + 1] = 0;
                }
                xp_SetFilePointer(hFile, position + i + 1, 0, XP_FILE_BEGIN);
                return TRUE;
            }
        }
        return TRUE;
    }
#else
    if ( fgets((char*)lpBuffer, nNumberOfBytesToRead, (FILE*)hFile) == NULL )
        return FALSE;
    return TRUE;
#endif
}

BOOL tscrypto::xp_WriteFile(XP_FILE hFile,
               const void * lpBuffer,
               uint32_t nNumberOfBytesToWrite,
               uint32_t * lpNumberOfBytesWritten,
               void * lpOverlapped)
{
    if ( hFile == XP_FILE_INVALID )
        return FALSE;
#ifdef _WIN32
    return WriteFile((HANDLE)hFile, lpBuffer, nNumberOfBytesToWrite, (DWORD*)lpNumberOfBytesWritten, (OVERLAPPED*)lpOverlapped);
#else
    *lpNumberOfBytesWritten = fwrite(lpBuffer, 1, nNumberOfBytesToWrite, (FILE*)hFile);
    if (*lpNumberOfBytesWritten != nNumberOfBytesToWrite)
    {
        return FALSE;
    }
    return TRUE;
#endif
}

uint32_t tscrypto::xp_SetFilePointer(XP_FILE hFile,
                            int32_t lDistanceToMove,
                            int32_t *lpDistanceToMoveHigh,
                            uint32_t dwMoveMethod)
{
    if ( hFile == XP_FILE_INVALID )
        return FALSE;
#ifdef _WIN32
    return SetFilePointer((HANDLE)hFile, lDistanceToMove, (PLONG)lpDistanceToMoveHigh, dwMoveMethod);
#else
    int origin;
    switch (dwMoveMethod)
    {
        case XP_FILE_BEGIN:
            origin = SEEK_SET;
            break;
        case XP_FILE_CURRENT:
            origin = SEEK_CUR;
            break;
        case XP_FILE_END:
            origin = SEEK_END;
            break;
        default:
            fprintf(stderr, "Illegal dwMoveMethod passed in: %u\n", dwMoveMethod);
            return XP_INVALID_SET_FILE_POINTER;
    }

    fseek((FILE*)hFile, lDistanceToMove, origin);

    return ftell((FILE*)hFile);
#endif
}

//BOOL CloseHandle(HANDLE hObject)
//{
//    fclose((FILE*)hObject);
//    return TRUE;
//}

uint32_t tscrypto::xp_GetFileSize(XP_FILE hFile,
                         uint32_t * lpFileSizeHigh)
{
    if ( hFile == XP_FILE_INVALID )
        return FALSE;
#ifdef _WIN32
    return GetFileSize((HANDLE)hFile, (DWORD*)lpFileSizeHigh);
#else
    struct stat stBuff;

    if (0 == fstat(fileno((FILE*)hFile), &stBuff))
    {
        return stBuff.st_size;
    }

    return 0;
#endif
}

BOOL tscrypto::xp_CloseFile(XP_FILE hObject)
{
    if ( hObject == XP_FILE_INVALID )
        return FALSE;
#ifdef _WIN32
    CloseHandle((HANDLE)hObject);
#else
    fclose((FILE*)hObject);
#endif
    return TRUE;
}

BOOL tscrypto::xp_LockFile(XP_FILE fileHandle)
{
    if ( fileHandle == XP_FILE_INVALID )
        return FALSE;
#ifdef _WIN32
    else
    {
        OVERLAPPED ov;
        HANDLE Event = CreateEvent(NULL, TRUE, FALSE, NULL);
        DWORD count;

        memset (&ov, 0, sizeof(ov));
        ov.Offset = 0;
        ov.OffsetHigh = 0;
        ov.hEvent = Event;

        if ( !LockFileEx((HANDLE)fileHandle, LOCKFILE_EXCLUSIVE_LOCK, 0, 0xFFFFFFFF, 0, &ov) )
        {
            if ( GetLastError() == ERROR_IO_PENDING )
            {
                if ( !GetOverlappedResult((HANDLE)fileHandle, &ov, &count, TRUE) )
                {
					if (Event != nullptr)
						CloseHandle(Event);
                    return FALSE;
                }
            }
            else
            {
				if (Event != nullptr)
					CloseHandle(Event);
                return FALSE;
            }
        }
        if (Event != nullptr)
            CloseHandle(Event);
    }
    return TRUE;
#else
    flockfile((FILE*)fileHandle);
    return TRUE;
#endif
}

BOOL tscrypto::xp_UnlockFile(XP_FILE fileHandle)
{
    if ( fileHandle == XP_FILE_INVALID )
        return FALSE;
#ifdef _WIN32
    if ( !UnlockFile((HANDLE)fileHandle, 0, 0, 0xffffffff, 0) )
    {
        return FALSE;
    }
    return TRUE;
#else
    funlockfile((FILE*)fileHandle);
    return TRUE;
#endif
}

uint32_t tscrypto::xp_GetFullPathName(const tsCryptoStringBase &lpFileName, tsCryptoStringBase &lpBuffer, char **lpFilePart)
{
#ifdef _WIN32
	lpBuffer.clear();
	lpBuffer.resize(MAX_PATH);
    uint32_t retVal = GetFullPathNameA(lpFileName.c_str(), (DWORD)lpBuffer.size(), lpBuffer.rawData(), lpFilePart);
	lpBuffer.resize(TsStrLen(lpBuffer.c_str()));
	return retVal;
#elif defined(__APPLE__)
    lpBuffer.clear();
    lpBuffer.resize(PATH_MAX * 4);
    realpath(lpFileName.data(), lpBuffer.data());
    lpBuffer.resize(strlen(lpBuffer.data()));
    
    if ( lpFilePart != NULL )
    {
        if ( strrchr(lpBuffer.c_str(), '/') != NULL )
        {
            *lpFilePart = strrchr(lpBuffer.rawData(), '/') + 1;
        }
        else
        {
            *lpFilePart = lpBuffer.rawData();
        }
    }
    return lpBuffer.size();
#else
    lpBuffer = lpFileName;

    
    if ( lpFilePart != NULL )
    {
        if ( strrchr(lpBuffer.c_str(), '/') != NULL )
        {
            *lpFilePart = strrchr(lpBuffer.rawData(), '/') + 1;
        }
        else
        {
            *lpFilePart = lpBuffer.rawData();
        }
    }
    return lpBuffer.size();
#endif
}

uint32_t tscrypto::xp_GetShortPathName(const tsCryptoStringBase &lpFileName, tsCryptoStringBase &lpBuffer)
{
#ifdef _WIN32
	lpBuffer.clear();
	lpBuffer.resize(MAX_PATH);
    uint32_t retVal = GetShortPathNameA(lpFileName.c_str(), lpBuffer.rawData(), (DWORD)lpBuffer.size());
	lpBuffer.resize(TsStrLen(lpBuffer.c_str()));
	return retVal;
#else
    lpBuffer = lpFileName;
    return lpBuffer.size();
#endif
}

uint32_t tscrypto::xp_GetLongPathName(const tsCryptoStringBase &lpFileName, tsCryptoStringBase &lpBuffer)
{
#ifdef _WIN32
    typedef uint32_t (STDMETHODCALLTYPE *fn)(const char *shortPath, char *path, int pathLen);
    fn Func;

    if ( kernelModule == 0 )
    {
        kernelModule = GetModuleHandleA(("KERNEL32.DLL"));
    }
    if ( kernelModule == 0 )
        return FALSE;
    Func = (fn)GetProcAddress(kernelModule, "GetLongPathNameA");
    if ( Func == 0 )
        return FALSE;
	lpBuffer.clear();
	lpBuffer.resize(MAX_PATH);
    uint32_t retVal = Func(lpFileName.c_str(), lpBuffer.rawData(), (int)lpBuffer.size());
	lpBuffer.resize(TsStrLen(lpBuffer.c_str()));
	return retVal;
#else
    lpBuffer = lpFileName;
    return lpBuffer.size();
#endif
}

void tscrypto::xp_GetTempPath(tsCryptoStringBase &path)
{
	path.clear();
	path.resize(MAX_PATH);

#ifdef _WIN32
	GetTempPathA((DWORD)path.size(), path.rawData());
	path.resize(TsStrLen(path.c_str()));
#else
    path = "/tmp/";
#endif
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

BOOL     tscrypto::xp_GetBootDriveRoot(tsCryptoStringBase &path)
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
        return FALSE;
    Func = (fn)GetProcAddress(kernelModule, "GetSystemWindowsDirectoryA");
    if ( Func == 0 )
        return FALSE;
    Func(localPath, sizeof(localPath) / sizeof(localPath[0]));
    if ( localPath[1] == ':' && localPath[2] == XP_PATH_SEP_CHAR )
        localPath[3] = 0;
	path = localPath;
    return TRUE;
#else
    path = XP_PATH_SEP_STR;
    return TRUE;
#endif
}

BOOL     tscrypto::xp_PathSearch(const tsCryptoStringBase &fileName, tsCryptoStringBase &path)
{
    tsCryptoString tmpPath;
    char *p;
#ifndef _WIN32
    char *p1;
#endif

    if ( xp_GetModuleFileName(XP_MODULE_INVALID, tmpPath) )
    {
		if ( TsStrrChr(tmpPath, XP_PATH_SEP_CHAR) != 0 )
        {
            TsStrrChr(tmpPath.rawData(), XP_PATH_SEP_CHAR)[1] = 0;
			tmpPath.resize(TsStrLen(tmpPath));
            tmpPath += fileName;
            if ( xp_FileExists(tmpPath) )
            {
				path = tmpPath;
                return TRUE;
            }
        }
    }
	//if (hExeInstance != XP_MODULE_INVALID)
 //   {
 //       if ( xp_GetModuleFileName(hExeInstance, tmpPath) )
 //       {
 //           if ( TsStrrChr(tmpPath, XP_PATH_SEP_CHAR) != 0 )
 //           {
 //               TsStrrChr(tmpPath, XP_PATH_SEP_CHAR)[1] = 0;
	//			tmpPath.resize(TsStrLen(tmpPath));
	//			tmpPath += fileName;
	//			if ( xp_FileExists(tmpPath) )
 //               {
	//				path = tmpPath;
	//				return TRUE;
 //               }
 //           }
 //       }
 //   }

    xp_GetSpecialFolder(sft_CommonFiles, tmpPath);
    tmpPath += fileName;
    if ( xp_FileExists(tmpPath) )
    {
		path = tmpPath;
        return TRUE;
    }

#ifdef _WIN32
    // AppPath
    // Path environment var
    // ProgFiles
    //
    // Can use the function SearchPath
	tmpPath.clear();
	tmpPath.resize(MAX_PATH);
    if ( SearchPathA(NULL, fileName.c_str(), NULL, (DWORD)tmpPath.size(), tmpPath.rawData(), &p) != 0 )
    {
		path = tmpPath;
        return TRUE;
    }

    xp_GetSpecialFolder(sft_CkmDefaultProgramsPath, tmpPath);
	tmpPath += fileName;
    if ( xp_FileExists(tmpPath) )
    {
		path = tmpPath;
        return TRUE;
    }
#else
    tsCryptoString envPath = getenv("PATH");
    p = envPath.rawData();
    while (p != 0 && p[0] != 0)
    {
        p1 = strchr(p, ':');

        if ( p1 != 0 )
        {
            *p1 = 0;
            p1++;
        }

        tmpPath = p;
        if ( tmpPath[tmpPath.size() - 1] != XP_PATH_SEP_CHAR )
            tmpPath << XP_PATH_SEP_STR;
        tmpPath << fileName;
        if ( xp_FileExists(tmpPath) )
        {
            path = tmpPath;
            return TRUE;
        }

        p = p1;
    }

#endif

    xp_GetSpecialFolder(sft_TecSecFolder, tmpPath);
    tmpPath += fileName;
    if ( xp_FileExists(tmpPath) )
    {
		path = tmpPath;
        return TRUE;
    }

    return FALSE;
}

// #if defined(_WIN32) && !defined(_MSC_VER)
// extern "C" BOOL WINAPI GetFileSizeEx(
//     HANDLE hFile,
//     PLARGE_INTEGER lpFileSize
// );
// #endif

int64_t  tscrypto::xp_GetFileSize64FromHandle(XP_FILE hFile)
{
#ifdef _WIN32
    LARGE_INTEGER size;

    if ( !GetFileSizeEx((HANDLE)hFile, &size) )
        size.QuadPart = 0;
    return size.QuadPart;
#elif defined(HAVE_FTELLO64)
	int64_t posi = ftello64((FILE*)hFile);
	fseeko64((FILE*)hFile, 0, SEEK_END);
	int64_t len = ftello64((FILE*)hFile);
	fseeko64((FILE*)hFile, posi, SEEK_SET);
	return len;
#elif defined(HAVE__FTELLI64)
    int64_t posi = _ftelli64((FILE*)hFile);
    _fseeki64((FILE*)hFile, 0, SEEK_END);
    int64_t len = _ftelli64((FILE*)hFile);
    _fseeki64((FILE*)hFile, posi, SEEK_SET);
    return len;
#else
	long posi = ftell((FILE*)hFile);
	fseek((FILE*)hFile, 0, SEEK_END);
	long len = ftell((FILE*)hFile);
	fseek((FILE*)hFile, posi, SEEK_SET);
	return len;
#endif
}

BOOL     tscrypto::xp_SearchThisPath(const tsCryptoStringBase &fileName, const tsCryptoStringBase &pathToSearch, tsCryptoStringBase &path)
{
    char iPath[1025];
    tsCryptoString envPath;
    char *p;
    char *p1;

    if ( fileName.size() == 0 || pathToSearch.size() == 0 )
        return FALSE;

	path.clear();

	envPath = pathToSearch;
	p = envPath.rawData();
    while (p != 0 && p[0] != 0)
    {
        p1 = TsStrChr(p, XP_PATHLIST_SEPARATOR);

        if ( p1 != 0 )
        {
            *p1 = 0;
            p1++;
        }

        TsStrCpy(iPath, sizeof(iPath) / sizeof(iPath[0]), p);
        if ( iPath[TsStrLen(iPath) - 1] != XP_PATH_SEP_CHAR )
            TsStrCat(iPath, sizeof(iPath) / sizeof(iPath[0]), XP_PATH_SEP_STR);
        TsStrCat(iPath, sizeof(iPath) / sizeof(iPath[0]), fileName);
        if ( xp_FileExists(iPath) )
        {
			path = iPath;
            return TRUE;
        }

        p = p1;
    }
    return FALSE;
}

bool tscrypto::xp_ReadAllText(const tsCryptoStringBase& filename, tsCryptoStringBase& contents)
{
    XP_FILE file = xp_CreateFile(filename, XP_GENERIC_READ, XP_FILE_SHARE_READ, nullptr, XP_OPEN_EXISTING, XP_FILE_ATTRIBUTE_NORMAL, nullptr);
    uint32_t count;

    if (file == XP_FILE_INVALID)
        return false;

    int64_t size = xp_GetFileSize64FromHandle(file);
    if (size > 0x7fffffff)
    {
        xp_CloseFile(file);
        return false;
    }
	contents.resize((size_t)size);
    if (!xp_ReadFile(file, contents.rawData(), (uint32_t)size, &count, nullptr))
    {
        contents.clear();
        xp_CloseFile(file);
        return false;
    }
    contents.resize(count);
    xp_CloseFile(file);
    return true;
}

bool tscrypto::xp_ReadAllBytes(const tsCryptoStringBase& filename, tsCryptoData& contents)
{
    XP_FILE file = xp_CreateFile(filename, XP_GENERIC_READ, XP_FILE_SHARE_READ, nullptr, XP_OPEN_EXISTING, XP_FILE_ATTRIBUTE_NORMAL, nullptr);
    uint32_t count;

    if (file == XP_FILE_INVALID)
        return false;

    int64_t size = xp_GetFileSize64FromHandle(file);
    if (size > 0x7fffffff)
    {
        xp_CloseFile(file);
        return false;
    }
	contents.resize((size_t)size);
    if (!xp_ReadFile(file, contents.rawData(), (uint32_t)size, &count, nullptr))
    {
        contents.clear();
        xp_CloseFile(file);
        return false;
    }
    contents.resize(count);
    xp_CloseFile(file);
    return true;
}

bool tscrypto::xp_AppendText(const tsCryptoStringBase& filename, const tsCryptoStringBase& contents)
{
    if (contents.size() == 0)
        return true;

    XP_FILE file = xp_CreateFile(filename, XP_GENERIC_WRITE, XP_FILE_SHARE_READ, nullptr, XP_OPEN_ALWAYS, XP_FILE_ATTRIBUTE_NORMAL, nullptr);
    uint32_t count;

    if (file == XP_FILE_INVALID)
        return false;

    xp_SetFilePointer(file, 0, nullptr, SEEK_END);
	if (!xp_WriteFile(file, contents.c_str(), (uint32_t)contents.size(), &count, nullptr) || count != (uint32_t)contents.size())
    {
        xp_CloseFile(file);
        return false;
    }
    xp_CloseFile(file);
    return true;
}

bool tscrypto::xp_AppendBytes(const tsCryptoStringBase& filename, const tsCryptoData& contents)
{
    if (contents.size() == 0)
        return true;

    XP_FILE file = xp_CreateFile(filename, XP_GENERIC_WRITE, XP_FILE_SHARE_READ, nullptr, XP_OPEN_ALWAYS, XP_FILE_ATTRIBUTE_NORMAL, nullptr);
    uint32_t count;

    if (file == XP_FILE_INVALID)
        return false;

    xp_SetFilePointer(file, 0, nullptr, SEEK_END);
	if (!xp_WriteFile(file, contents.c_str(), (uint32_t)contents.size(), &count, nullptr) || count != (uint32_t)contents.size())
    {
        xp_CloseFile(file);
        return false;
    }
    xp_CloseFile(file);
    return true;
}

bool tscrypto::xp_WriteText(const tsCryptoStringBase& filename, const tsCryptoStringBase& contents)
{
    XP_FILE file = xp_CreateFile(filename, XP_GENERIC_WRITE, XP_FILE_SHARE_READ, nullptr, XP_CREATE_ALWAYS, XP_FILE_ATTRIBUTE_NORMAL, nullptr);
    uint32_t count;

    if (file == XP_FILE_INVALID)
        return false;

	if (!xp_WriteFile(file, contents.c_str(), (uint32_t)contents.size(), &count, nullptr) || count != (uint32_t)contents.size())
    {
        xp_CloseFile(file);
        return false;
    }
    xp_CloseFile(file);
    return true;
}

bool tscrypto::xp_WriteBytes(const tsCryptoStringBase& filename, const tsCryptoData& contents)
{
    XP_FILE file = xp_CreateFile(filename, XP_GENERIC_WRITE, XP_FILE_SHARE_READ, nullptr, XP_CREATE_ALWAYS, XP_FILE_ATTRIBUTE_NORMAL, nullptr);
    uint32_t count;

    if (file == XP_FILE_INVALID)
        return false;

    if (!xp_WriteFile(file, contents.c_str(), (uint32_t)contents.size(), &count, nullptr) || count != (uint32_t)contents.size())
    {
        xp_CloseFile(file);
        return false;
    }
    xp_CloseFile(file);
    return true;
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


BOOL tscrypto::xp_GetCurrentDirectory(tsCryptoStringBase& path)
{
#ifdef HAVE_WINDOWS_H
    path.clear();
    path.resize(MAX_PATH);
	if (!GetCurrentDirectoryA((DWORD)path.size(), path.rawData()))
        return FALSE;
    path.resize(strlen(path.c_str()));
    return TRUE;
#elif defined(HAVE_GETCWD)
    path.clear();
    path.resize(1024);
    if (getcwd(path.rawData(), path.size()) == nullptr)
        return FALSE;
    path.resize(strlen(path.c_str()));
    return TRUE;
#else
    #error Need a way to get the current working directory
#endif // HAVE_WINDOWS_H
}
BOOL tscrypto::xp_SetCurrentDirectory(const tsCryptoStringBase& setTo)
{
#ifdef HAVE_WINDOWS_H
    return SetCurrentDirectoryA(setTo.c_str());
#elif defined(HAVE_CHDIR)
    if (chdir(setTo.c_str()) != 0)
        return FALSE;
    return TRUE;
#else
    #error Need a way to change the current working directory
#endif // HAVE_WINDOWS_H
}
BOOL tscrypto::xp_MoveFile(const tsCryptoStringBase& source, const tsCryptoStringBase& destination)
{
#ifdef _WIN32
	if (0 != CopyFileA(source.c_str(), destination.c_str(), false))  // don't overwrite existing file
	{
		xp_DeleteFile(source);
		return TRUE;
	}
    return FALSE;
#else
    if (rename(source.c_str(), destination.c_str()))
    {
        if (errno == EXDEV)
        {
            // Rename failed because the source and destination devices are different
            tsCryptoData buffer;

            int64_t size = xp_GetFileSize(source.c_str());

            if (size < 500000)
            {
                if (!xp_ReadAllBytes(source, buffer))
                {
                    return FALSE;
                }
                if (!xp_WriteBytes(destination, buffer))
                {
                    return FALSE;
                }
                if (!xp_DeleteFile(source))
                {
                    return FALSE;
                }
                return true;
            }
            else
            {
                XP_FILE src, dst;
                int64_t posi = 0;

                buffer.resize(102400);
                src = xp_CreateFile(source, XP_GENERIC_READ, XP_FILE_SHARE_READ, nullptr, XP_OPEN_EXISTING, XP_FILE_ATTRIBUTE_NORMAL, nullptr);

                if (src == XP_FILE_INVALID)
                {
                    return FALSE;
                }

                dst = xp_CreateFile(destination, XP_GENERIC_WRITE, XP_FILE_SHARE_READ, nullptr, XP_CREATE_ALWAYS, XP_FILE_ATTRIBUTE_NORMAL, nullptr);
                if (dst == XP_FILE_INVALID)
                {
                    xp_CloseFile(src);
                    return FALSE;
                }

                while (posi < size)
                {
                    uint32_t bufferSize = 102400;
                    uint32_t count = 0;

                    if (size - posi < (int64_t)bufferSize)
                    {
                        bufferSize = (uint32_t)(size - posi);
                        buffer.resize(bufferSize);
                    }

                    if (!xp_ReadFile(src, buffer.rawData(), bufferSize, &count, nullptr) || count != bufferSize)
                    {
                        xp_CloseFile(dst);
                        xp_DeleteFile(destination);
                        xp_CloseFile(src);
                        return FALSE;
                    }
                    if (!xp_WriteFile(dst, buffer.c_str(), (uint32_t)buffer.size(), &count, nullptr) || count != (uint32_t)buffer.size())
                    {
                        xp_CloseFile(dst);
                        xp_DeleteFile(destination);
                        xp_CloseFile(src);
                        return FALSE;
                    }
                    posi += bufferSize;
                }
                xp_CloseFile(src);
                xp_CloseFile(dst);
                xp_DeleteFile(source);
                return TRUE;
            }
        }
        else
        {
            return FALSE;
        }
    }
    else
        return TRUE;
#endif // _WIN32
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
