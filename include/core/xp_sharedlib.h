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

////////////////////////////////////////////////////////////////////////////////////////////////////
/// \file   xp_sharedlib.h
///
/// \brief  Declares the shared library functions
////////////////////////////////////////////////////////////////////////////////////////////////////

#ifndef __XP_SHAREDLIB_H__
#define __XP_SHAREDLIB_H__

#pragma once

namespace tscrypto {

//#ifdef _WIN32
//	/// <summary>the handle to the exe or a dll loaded in memory.</summary>
//	struct __xp_module {};
//	typedef ID<__xp_module, HINSTANCE, nullptr> XP_MODULE;
//#else
//	struct __xp_module {};
//	typedef ID<__xp_module, void*, (void*)nullptr> XP_MODULE;
//#endif
//	/// <summary>The invalid module handle value</summary>
//#define XP_MODULE_INVALID XP_MODULE::invalid()


	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Cross platform function used to retrieve the command line parameters used to start the application</summary>
	///
	/// <returns>the parameters in a string</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsCryptoString VEILCORE_API xp_GetCommandLine();
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Cross platform function used to get the module handle for a dll (shared library) with the given name</summary>
	///
	/// <param name="moduleName">Name of the module.</param>
	///
	/// <returns>XP_MODULE_INVALID for failure or the module handle</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	//XP_MODULE     VEILCORE_API xp_GetModuleHandle(const tsCryptoStringBase &moduleName);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Cross platform function used to get the current process ID</summary>
	///
	/// <returns>the current process ID</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	uint32_t      VEILCORE_API xp_GetCurrentProcessId();
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Cross platform function used to get the current thread ID</summary>
	///
	/// <returns>the current thread ID</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	uint32_t      VEILCORE_API xp_GetCurrentThreadId();


}

#endif //__XP_SHAREDLIB_H__
