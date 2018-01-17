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

AttributeSelectorGridWrapper::AttributeSelectorGridWrapper() : _parent(nullptr), _dlg(nullptr)
{
	vars._cryptoGroupId.clear();
	vars._selectedAttributeCount = 0;
}
AttributeSelectorGridWrapper::~AttributeSelectorGridWrapper()
{
	Destroy();
}

// wxDialog
bool AttributeSelectorGridWrapper::Destroy()
{
	if (_dlg != nullptr)
	{
		_dlg->Close();
	}
	_dlg = nullptr;
	_parent = XP_WINDOW_INVALID;
	vars._session.reset();
	vars._cryptoGroupId.clear();
	vars._ckm7group.reset();
	vars._attrsList.reset();
	vars._selectedAttributeCount = 0;
	return true;
}
// IVEILWxUIBase
int  AttributeSelectorGridWrapper::DisplayModal()
{
	std::shared_ptr<tsmod::IObject>	Me; // Keep me alive until Destroy is called

	if (_dlg != nullptr)
	{
		return 0;
	}
	Me = _me.lock();
	if (_parent == XP_WINDOW_INVALID)
		_parent = (XP_WINDOW)wxTheApp->GetTopWindow();

	// Construct the dialog here
	_dlg = new AttributeSelectorGrid();
	_dlg->setVariables(&vars);

	_dlg->Create((wxWindow*)_parent);

	int retVal = _dlg->ShowModal();

	// Make sure you call Destroy
	Destroy();
	return retVal;
}
int  AttributeSelectorGridWrapper::DisplayModal(XP_WINDOW wnd) 
{
	_parent = wnd;
	return DisplayModal();
}

// IAudienceSelector
bool AttributeSelectorGridWrapper::Start(std::shared_ptr<IKeyVEILSession> session, XP_WINDOW parent, const tscrypto::tsCryptoData& CryptoGroupId, std::shared_ptr<ICmsHeaderAttributeGroup> group, std::shared_ptr<ICmsHeaderAttributeListExtension> attrList)
{
	if (session == NULL || group == NULL)
		return false;

	if (!session->IsLoggedIn())
		return false;

	vars._cryptoGroupId = CryptoGroupId;
	vars._ckm7group = group;
	vars._attrsList = attrList;
	vars._session = session;
	vars._selectedAttributeCount = 0;

	return true;
}

tsmod::IObject* CreateAttributeSelectorGrid()
{
	return dynamic_cast<tsmod::IObject*>(new AttributeSelectorGridWrapper());
}
