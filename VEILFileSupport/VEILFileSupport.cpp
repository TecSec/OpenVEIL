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
#include "VEILFileSupportFactory.h"

#ifndef VEILFILESUPPORT_STATIC
#ifdef _WIN32
extern "C"
BOOL __stdcall DllMain( HINSTANCE hModule,
                       DWORD  ul_reason_for_call,
                       void * /*lpReserved*/
					 )
{
    if ( ul_reason_for_call == DLL_PROCESS_ATTACH )
    {
    }
	if (ul_reason_for_call == DLL_PROCESS_DETACH)
	{
	}
    return TRUE;
}
#endif
#endif // VEILFILESUPPORT_STATIC

class VEILFileSupportDllInterface : public IVEILFileSupportDllInterface, public tsmod::IObject
{
public:
	VEILFileSupportDllInterface()
	{
	}
	virtual ~VEILFileSupportDllInterface(void)
	{
	}

	// IVEILFileSupportDllInterface
    virtual bool InitializeVEILFileSupport()
	{
		return true;
	}

    virtual bool TerminateVEILFileSupport()
	{
		//tsCrypto::TSTerminateCrypto();

		return true;
	}

	virtual bool GetVEILFileSupportFactory(std::shared_ptr<IVEILFileSupportFactory>& pVal)
	{
		pVal = CreateVEILFileSupportFactory();
		return !!pVal;
	}
};

FileVEILFileOp_recoveredKeyList CreateFileVEILFileOp_recoveredKeyList()
{
	return CreateContainer<FileVEILFileOp_recoveredKey>();
}

#if __GNUC__ >= 4
//extern "C"
#endif
EXPORT_SYMBOL std::shared_ptr<IVEILFileSupportDllInterface> GetVEILFileSupportDllInterface()
{
	if (!::TopServiceLocator()->CanCreate("/VEILFileSupportDllInterface"))
	{
		::TopServiceLocator()->AddSingletonClass("/VEILFileSupportDllInterface", []() { return dynamic_cast<tsmod::IObject*>(new VEILFileSupportDllInterface()); });
		AddSystemTerminationFunction([]() ->bool { ::TopServiceLocator()->DeleteClass("/VEILFileSupportDllInterface"); return true; });
	}
	return ::TopServiceLocator()->get_instance<IVEILFileSupportDllInterface>("/VEILFileSupportDllInterface");
}
