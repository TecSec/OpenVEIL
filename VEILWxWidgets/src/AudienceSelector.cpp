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
//#include "help/VEILSystemHelp.h"

class AudienceSelectorWrapper : public IAudienceSelector, public tsmod::IObject
{
public:
	AudienceSelectorWrapper(bool createFavorites) : _cookie(0), _dlg(nullptr)
	{
		_vars._favoriteManager = createFavorites;
		_vars._hideKeyVEILLogin = false;
	}
	virtual ~AudienceSelectorWrapper()
	{
		Destroy();
	}
	virtual void OnConstructionFinished() override
	{
		if (!::TopServiceLocator()->CanCreate("/CmsHeader"))
		{
			InitializeCmsHeader();
		}
		_vars._header = ::TopServiceLocator()->get_instance<ICmsHeader>("/CmsHeader");
	}

	// wxDialog
	virtual bool Destroy() override
	{
		_parent = XP_WINDOW_INVALID;
		_vars._session.reset();
		if (!!_vars._connector && _cookie != 0)
		{
			_vars._connector->RemoveKeyVEILChangeCallback(_cookie);
			_cookie = 0;
		}
		_vars._favoriteManager = false;
		//_AppName.clear();
		return true;
	}
	// IVEILWxUIBase
	virtual int  DisplayModal() override
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
		_dlg = new AudienceSelectorDlg();
		_dlg->setVariables(&_vars);

		// TODO:  Create linkages and transfer variables here   	OnInitDialog();

		_dlg->Create((wxWindow*)_parent);

		int retVal = _dlg->ShowModal();

		// Make sure you call Destroy
		Destroy();
		return retVal;
	}
	virtual int  DisplayModal(XP_WINDOW wnd) override
	{
		_parent = wnd;
		return DisplayModal();
	}

	// IAudienceSelector
	virtual std::shared_ptr<IKeyVEILConnector> Connector() override
	{
		return _vars._connector;
	}
	virtual void Connector(std::shared_ptr<IKeyVEILConnector> setTo) override
	{
		_vars._connector.reset();
		_vars._session.reset();
		_vars._connector = setTo;
	}
	virtual std::shared_ptr<IKeyVEILSession> Session() override
	{
		return _vars._session;
	}
	bool HasSession() const
	{
		return !!_vars._session;
	}
	virtual void Session(std::shared_ptr<IKeyVEILSession> setTo) override
	{
		_vars._session.reset();
		_vars._session = setTo;

	}
	virtual tscrypto::tsCryptoData HeaderData() override
	{
		return _vars._header->ToBytes();
	}
	virtual void HeaderData(const tscrypto::tsCryptoData& setTo) override
	{
		if (!_vars._header->FromBytes(setTo))
			_vars._header->Clear();
	}
	virtual std::shared_ptr<ICmsHeader> Header() override
	{
		return _vars._header;
	}
	virtual void Header(std::shared_ptr<ICmsHeader> setTo) override
	{
		_vars._header.reset();
		_vars._header = setTo;
	}
	virtual bool Start(std::shared_ptr<IKeyVEILConnector> connector, XP_WINDOW parent, const tscrypto::tsCryptoString& appName) override
	{
		if (!!connector)
		{
			Connector(connector);
			_cookie = _vars._connector->AddKeyVEILChangeCallback([this](JSONObject& eventData) {
				if (_dlg != nullptr)
				{
					if (eventData.AsString("type") == "Token")
					{
						if (eventData.AsString("event") == "add")
						{
							_dlg->OnTokenAdd(eventData.AsString("serial").HexToData());
						}
						else if (eventData.AsString("event") == "delete")
						{
							_dlg->OnTokenRemove(eventData.AsString("serial").HexToData());
						}
						else
						{
							//_dlg->OnTokenDataChange(eventData.AsString("serial").HexToData());
						}
					}
					else if (eventData.AsString("type") == "Favorite")
					{
						_dlg->InitFavorites();
						// OnFavoriteAdd
					}
				}
			});
		}
		_parent = parent;
		//_AppName = appName;

		if (!_vars._connector)
			return false;

		return true;
	}
	virtual void HideKeyVEILLogin(bool setTo) override
	{
		_vars._hideKeyVEILLogin = setTo;
	}

private:

	XP_WINDOW										_parent;
	AudienceSelectorDlg* _dlg;
	audienceSelector2Variables                      _vars;
	size_t											_cookie;
};

tsmod::IObject* CreateAudienceSelector()
{
	return dynamic_cast<tsmod::IObject*>(new AudienceSelectorWrapper(false));
}
tsmod::IObject* CreateFavoriteEditer()
{
	return dynamic_cast<tsmod::IObject*>(new AudienceSelectorWrapper(true));
}