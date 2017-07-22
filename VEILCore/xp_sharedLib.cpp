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

#ifdef DMALLOC
#include <dmalloc.h>
#endif

using namespace tscrypto;

#ifndef _WIN32
    extern const char *gLastDLError;
#endif // _WIN32
/*
 * Get the address of a specified procedure from the shared library
 */
extern ProcAddressFn tscrypto::xp_GetProcAddress(XP_MODULE phDll, const char *procName)
{
#ifdef _WIN32
	return (ProcAddressFn)GetProcAddress((HINSTANCE)phDll, procName);
#else /* UNIX */
    Dl_info info = {0,};

    //printf ("looking for proc %s\n", procName);
	ProcAddressFn retVal = (ProcAddressFn)dlsym((void *)phDll, procName);
    // if (retVal == nullptr)
    // {
    //     if (dladdr((void*)phDll, &info) != 0)
    //         printf ("  not found - %s - %s\n", dlerror(), info.dli_fname);
    //     else
    //         printf ("  not found - %s - %s\n", dlerror(), "UNKNOWN");
    // }
    // else
    //     printf ("  found %p - %s\n", retVal, info.dli_fname);
    return retVal;
#endif
}

/*
 * Load a shared library (DLL) to get a HANDLE to it
 */
extern int32_t tscrypto::xp_LoadSharedLib(const tsCryptoStringBase &pPath, XP_MODULE * phDll)
{
#ifdef _WIN32
    /* load the desired IA Object (DLL) */
	if (XP_MODULE_INVALID == (*phDll = (XP_MODULE)LoadLibraryExA(pPath.c_str(), nullptr, 0))) {
        return -1;
    }
#else
    void* p;
    #ifdef __APPLE__
        p = dlopen(pPath.c_str(), RTLD_NOW | RTLD_GLOBAL | RTLD_FIRST);
    #else
        p = dlopen(pPath.c_str(), RTLD_LAZY | RTLD_LOCAL);
    #endif
    *phDll = (XP_MODULE)p;
    if (NULL == p)
    {
        gLastDLError = dlerror();
        //printf ("Load of %s failed with %s\n", pPath.c_str(), gLastDLError);
        return -1;
    }
    else
    {
        //printf("Found module %s at %p\n", pPath.c_str(), p);
    gLastDLError = NULL;
    }
#endif
    return 0;
}


/*
 * Release a shared library (DLL) obtained by iLoadSharedLib
 */
extern uint32_t tscrypto::xp_FreeSharedLib(XP_MODULE hDll)
{
#ifdef _WIN32
    /* who cares if this fails */
	if (hDll != XP_MODULE_INVALID)
    {
        FreeLibrary((HINSTANCE)hDll);
    }
#else
    if (hDll != XP_MODULE_INVALID)
    {
        dlclose((void *)hDll);
        hDll = XP_MODULE_INVALID;
    }
#endif
    return 0;
}

#ifndef _WIN32
#ifdef __cplusplus
extern "C"
#endif
const char *GetLastDLError()
{
    return gLastDLError;
}
#endif // _WIN32

#ifdef __APPLE__
#include <mach-o/dyld.h>

static tsCryptoStringBase getexecpath()
{
    tsCryptoStringBase tmp;
    uint32_t size;
    
    tmp.resize(4 * PATH_MAX);
    size = (uint32_t)tmp.size();
    if (_NSGetExecutablePath(tmp.data(), &size) == 0)
    {
        tmp.resize(strlen(tmp.data()));
        tsCryptoStringBase tmp2(tmp);
        
        xp_GetFullPathName(tmp2, tmp, nullptr);
    }
    else
    {
        tmp.clear();
    }
    return tmp;
}
#elif !defined(_WIN32)
static const char* getexecpath()
{
      static char buf[30], execpath[2048];

      sprintf(buf,"/proc/%d/exe", getpid());
      memset(execpath, 0, sizeof(execpath));
      readlink(buf, execpath, sizeof(execpath));
      return execpath;
}
#endif

BOOL tscrypto::xp_GetModuleFileName(XP_MODULE module, tsCryptoStringBase &name)
{
#ifdef _WIN32
	name.clear();
	name.resize(MAX_PATH);
    BOOL retVal = GetModuleFileNameA((HINSTANCE)module, name.data(), (DWORD)name.size());
	name.resize(TsStrLen(name.c_str()));
	return retVal;
#else
    if ( module == XP_MODULE_INVALID )
    {
        tsCryptoStringBase path;

        path = getexecpath();
        if ( path.size() == 0 || path[0] == 0 )
            return FALSE;
        name = path;
        return TRUE;
    }
    else
    {
        Dl_info info;

        if ( !dladdr((void*)module,&info) )
        {
            return FALSE;
        }
        name = info.dli_fname;
        return TRUE;
    }
#endif
}

tsCryptoString tscrypto::xp_GetCommandLine()
{
#ifdef _WIN32
    return GetCommandLine();
#else
    return "";
#endif
}

XP_MODULE tscrypto::xp_GetModuleHandle(const tsCryptoStringBase &moduleName)
{
#ifdef _WIN32
	return (XP_MODULE)GetModuleHandleA(moduleName.c_str());
#else
    return XP_MODULE_INVALID;
#endif
}



uint32_t            tscrypto::xp_GetCurrentProcessId()
{
#ifdef _WIN32
    return GetCurrentProcessId();
#else
    return getpid();
#endif
}

uint32_t            tscrypto::xp_GetCurrentThreadId()
{
#ifdef _WIN32
    return GetCurrentThreadId();
#else
    return (uint32_t)(intptr_t)pthread_self();
#endif
}
