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

void FavoriteManagerWrapper::OnConstructionFinished()
{
	if (!::TopServiceLocator()->CanCreate("/CmsHeader"))
	{
		InitializeCmsHeader();
	}
	_vars._header = ::TopServiceLocator()->get_instance<ICmsHeader>("/CmsHeader");
}

bool FavoriteManagerWrapper::Destroy()
{
	if (!!_vars._connector && _cookie != 0)
	{
		_vars._connector->RemoveKeyVEILChangeCallback(_cookie);
		_cookie = 0;
	}

	if (_dlg != nullptr)
	{
		_dlg->Close();
	}
	_dlg = nullptr;
	return true;
}

int FavoriteManagerWrapper::DisplayModal()
{
	std::shared_ptr<tsmod::IObject>	Me; // Keep me alive until Destroy is called

	if (_dlg != nullptr)
	{
		return 0;
	}
	Me = _me.lock();
	if (_parent == XP_WINDOW_INVALID)
		_parent = (XP_WINDOW)wxTheApp->GetTopWindow();

	_vars._header->Clear();

	if (!_vars._connector)
	{
		_vars._connector = ::TopServiceLocator()->try_get_instance<IKeyVEILConnector>("KeyVEILConnector");
	}

	// Construct the dialog here
	_dlg = new FavoriteManagerDlg();
	_dlg->setVariables(&_vars);

	// TODO:  Create linkages and transfer variables here   	OnInitDialog();

	_dlg->Create((wxWindow*)_parent);

	int retVal = _dlg->ShowModal();

	// Make sure you call Destroy
	Destroy();
	return retVal;
}

int FavoriteManagerWrapper::DisplayModal(XP_WINDOW wnd)
{
	_parent = wnd;
	return DisplayModal();
}

std::shared_ptr<IKeyVEILConnector> FavoriteManagerWrapper::Connector()
{
	return _vars._connector;
}

void FavoriteManagerWrapper::Connector(std::shared_ptr<IKeyVEILConnector> setTo)
{
	_vars._connector.reset();
	_vars._session.reset();
	_vars._token.reset();
	// TODO: _profile.reset();
	_vars._connector = setTo;
}

std::shared_ptr<IKeyVEILSession> FavoriteManagerWrapper::Session()
{
	return _vars._session;
}

void FavoriteManagerWrapper::Session(std::shared_ptr<IKeyVEILSession> setTo)
{
	_vars._session.reset();
	_vars._token.reset();
	// TODO: _profile.reset();
	_vars._session = setTo;

	// TODO:  Update the _vars._token variable
}

tscrypto::tsCryptoData FavoriteManagerWrapper::HeaderData()
{
	return _vars._header->ToBytes();
}

void FavoriteManagerWrapper::HeaderData(const tscrypto::tsCryptoData & setTo)
{
	if (!_vars._header->FromBytes(setTo))
		_vars._header->Clear();
}

std::shared_ptr<ICmsHeader> FavoriteManagerWrapper::Header()
{
	return _vars._header;
}

void FavoriteManagerWrapper::Header(std::shared_ptr<ICmsHeader> setTo)
{
	_vars._header.reset();
	_vars._header = setTo;
}

bool FavoriteManagerWrapper::Start(std::shared_ptr<IKeyVEILConnector> connector, XP_WINDOW parent, const tscrypto::tsCryptoString & appName)
{
	if (!!connector)
	{
		Connector(connector);
		_cookie = connector->AddKeyVEILChangeCallback([this](JSONObject& eventData) {
			if (eventData.AsString("type") == "Favorite")
			{
				if (_dlg != nullptr)
					_dlg->ReloadFavorites();
				// OnFavoriteAdd
			}
		});
	}
	_parent = parent;
	_AppName = appName;

	if (!_vars._connector)
		return false;

	return true;
}

void FavoriteManagerWrapper::HideKeyVEILLogin(bool setTo)
{
	_vars._hideKeyVEILLogin = setTo;
}

tsmod::IObject* CreateFavoriteManager()
{
	return dynamic_cast<tsmod::IObject*>(new FavoriteManagerWrapper());
}
