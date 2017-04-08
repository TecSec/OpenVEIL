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
#include "VEILSmartCard.h"

static tsmod::IObject* CreateSmartCardTool()
{
	std::shared_ptr<tsmod::IVeilUtilities> utils = ::TopServiceLocator()->get_instance<tsmod::IVeilUtilities>("VeilUtilities");
	return utils->buildCommandMenu("Perform smart card operations", "/SMARTCARD-COMMANDS/", "smartcard", "SMARTCARD");
}

static tsmod::IObject* CreateSmartCardAIDTool()
{
	std::shared_ptr<tsmod::IVeilUtilities> utils = ::TopServiceLocator()->get_instance<tsmod::IVeilUtilities>("VeilUtilities");
	return utils->buildCommandMenu("Perform smart card AID operations", "/SMARTCARDAID-COMMANDS/", "aid", "SMARTCARD AID");
}
static tsmod::IObject* CreateSmartCardChangeTool()
{
	std::shared_ptr<tsmod::IVeilUtilities> utils = ::TopServiceLocator()->get_instance<tsmod::IVeilUtilities>("VeilUtilities");
	return utils->buildCommandMenu("Perform smart card CHANGE operations", "/SMARTCARDCHANGE-COMMANDS/", "change", "SMARTCARD CHANGE");
}
static tsmod::IObject* CreateSmartCardChangePasswordTool()
{
	std::shared_ptr<tsmod::IVeilUtilities> utils = ::TopServiceLocator()->get_instance<tsmod::IVeilUtilities>("VeilUtilities");
	return utils->buildCommandMenu("Perform smart card CHANGE PASSWORD operations", "/SMARTCARDCHANGEPASSWORD-COMMANDS/", "password", "SMARTCARD CHANGE PASSWORD");
}

extern tsmod::IObject* CreateChangeActPasswordTool();
extern tsmod::IObject* CreateSmartCardInfoTool();
extern tsmod::IObject* CreateListAIDTool();
extern tsmod::IObject* CreateAddAIDTool();
extern tsmod::IObject* CreateRemoveAIDTool();
extern tsmod::IObject* CreateSmartCardMonitorTool();


#ifdef _WIN32
#define EXPORTME __declspec(dllexport)
#else
#define EXPORTME EXPORT_SYMBOL
#endif

extern "C"
bool EXPORTME Initialize_smartcard(std::shared_ptr<tsmod::IServiceLocator> servLoc, tsmod::IReportError* log)
{
	UNREFERENCED_PARAMETER(servLoc);
	UNREFERENCED_PARAMETER(log);

	InitializeSmartCard();


	::TopServiceLocator()->AddClass("/COMMANDS/SMARTCARD", CreateSmartCardTool);

	::TopServiceLocator()->AddClass("/SMARTCARD-COMMANDS/AID", CreateSmartCardAIDTool);
	::TopServiceLocator()->AddClass("/SMARTCARD-COMMANDS/INFO", CreateSmartCardInfoTool);
	::TopServiceLocator()->AddClass("/SMARTCARD-COMMANDS/MONITOR", CreateSmartCardMonitorTool);

	::TopServiceLocator()->AddClass("/SMARTCARDAID-COMMANDS/LIST", CreateListAIDTool);
	::TopServiceLocator()->AddClass("/SMARTCARDAID-COMMANDS/ADD", CreateAddAIDTool);
	::TopServiceLocator()->AddClass("/SMARTCARDAID-COMMANDS/REMOVE", CreateRemoveAIDTool);

	if (::TopServiceLocator()->CanCreate("/Crypto/SECURE_CHANNEL-SERVER"))
	{
		::TopServiceLocator()->AddClass("/SMARTCARD-COMMANDS/CHANGE", CreateSmartCardChangeTool);

		::TopServiceLocator()->AddClass("/SMARTCARDCHANGE-COMMANDS/PASSWORD", CreateSmartCardChangePasswordTool);

		::TopServiceLocator()->AddClass("/SMARTCARDCHANGEPASSWORD-COMMANDS/ACTIVATION", CreateChangeActPasswordTool);
	}
	return true;
}

extern "C"
bool EXPORTME Terminate_smartcard(std::shared_ptr<tsmod::IServiceLocator> servLoc)
{
	UNREFERENCED_PARAMETER(servLoc);

	if (::HasServiceLocator())
	{
		::TopServiceLocator()->DeleteClass("/SMARTCARD-COMMANDS/AID");
		::TopServiceLocator()->DeleteClass("/SMARTCARD-COMMANDS/INFO");
		::TopServiceLocator()->DeleteClass("/SMARTCARD-COMMANDS/CHANGE");
		::TopServiceLocator()->DeleteClass("/SMARTCARD-COMMANDS/MONITOR");

		::TopServiceLocator()->DeleteClass("/SMARTCARDAID-COMMANDS/LIST");
		::TopServiceLocator()->DeleteClass("/SMARTCARDAID-COMMANDS/ADD");
		::TopServiceLocator()->DeleteClass("/SMARTCARDAID-COMMANDS/REMOVE");

		::TopServiceLocator()->DeleteClass("/SMARTCARDCHANGE-COMMANDS/PASSWORD");

		::TopServiceLocator()->DeleteClass("/SMARTCARDCHANGEPASSWORD-COMMANDS/ACTIVATION");
		::TopServiceLocator()->CleanEmptyCollections();
		::TopServiceLocator()->DeleteClass("/COMMANDS/SMARTCARD");
	}
	return true;
}

