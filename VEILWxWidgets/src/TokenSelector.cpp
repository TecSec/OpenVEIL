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

class TokenSelectorWrapper : public ITokenSelector, public tsmod::IObject
{
public:
	TokenSelectorWrapper() : _parent(XP_WINDOW_INVALID), _cookie(0), _dlg(nullptr)
	{
		_vars.m_enterpriseOID = GUID_NULL;
	}
	~TokenSelectorWrapper()
	{
	}

	// wxDialog
	virtual bool Destroy() override
	{
		if (!!_vars._connector && _cookie != 0)
		{
			_vars._connector->RemoveKeyVEILChangeCallback(_cookie);
			_cookie = 0;
		}
		if (_dlg != nullptr)
			delete _dlg;
		_dlg = nullptr;
		_vars.m_enterpriseOID = GUID_NULL;
		_vars.m_reason.clear();
		return true;
	}
	// IVEILWxUIBase
	virtual int  DisplayModal() override
	{
		std::shared_ptr<tsmod::IObject>	Me; // Keep me alive until Destroy is called

		if (_parent == XP_WINDOW_INVALID)
			_parent = (XP_WINDOW)wxTheApp->GetTopWindow();

		Me = _me.lock();
		// Construct the dialog here
		_dlg = new TokenSelectorDlg;
		auto cleanup = finally([this]() {
			if (_dlg != nullptr)
				delete _dlg;
			_dlg = nullptr;
		});
		if (!!_vars._connector)
		{
			_cookie = _vars._connector->AddKeyVEILChangeCallback([this](JSONObject& eventData) {
				if (eventData.AsString("type") == "Token")
				{
					if (_dlg != nullptr)
						_dlg->OnRefresh();
				}
			});
		}
		auto cleanup2 = finally([this]() {
			if (!!_vars._connector && _cookie != 0)
			{
				_vars._connector->RemoveKeyVEILChangeCallback(_cookie);
				_cookie = 0;
			}
		});
		_dlg->setVariables(&_vars);
		_dlg->Create((wxWindow*)_parent);

		int retVal = _dlg->ShowModal();
		session = _dlg->Session();

		return retVal;
	}
	virtual int  DisplayModal(XP_WINDOW wnd) override
	{
		_parent = wnd;
		return DisplayModal();
	}

	// ITokenSelector
	virtual bool Start(std::shared_ptr<IKeyVEILConnector> connector, const GUID& enterpriseId, const tscrypto::tsCryptoString& reason, XP_WINDOW parent) override
	{
		_vars._connector = connector;
		_vars.m_enterpriseOID = enterpriseId;
		_vars.m_reason = reason;

		return true;
	}
	virtual std::shared_ptr<IKeyVEILSession> Session() override
	{
		return session;
	}


private:
	size_t _cookie;

	XP_WINDOW				_parent;
	tokenSelectorVariables	_vars;
	std::shared_ptr<IKeyVEILSession> session;
	TokenSelectorDlg*		_dlg;
};

tsmod::IObject* CreateTokenSelector()
{
	return dynamic_cast<tsmod::IObject*>(new TokenSelectorWrapper());
}