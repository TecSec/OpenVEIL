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

class TokenLoginWrapper : public ITokenLogin, public tsmod::IObject
{
public:
	TokenLoginWrapper() : _parent(nullptr)
	{
		_vars._maxLen = 64;
		_vars._minLen = 6;
	}
	virtual ~TokenLoginWrapper() 
	{
	}

	// wxDialog
	virtual bool Destroy() override
	{
		_parent = XP_WINDOW_INVALID;
		_vars._session.reset();
		_vars._maxLen = 64;
		_vars._minLen = 6;
		_vars._pinBuffer.clear();
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
		TokenLogin dlg;
		dlg.setVariables(&_vars);
		dlg.Create((wxWindow*)_parent);

		int retVal = dlg.ShowModal();

		// Make sure you call Destroy
		Destroy();
		return retVal;
	}
	virtual int  DisplayModal(XP_WINDOW wnd) override
	{
		_parent = wnd;
		return DisplayModal();
	}

	// ITokenLogin
	virtual bool Start(std::shared_ptr<IKeyVEILSession> session, XP_WINDOW parent) override
	{
		if (!session || !session->GetProfile())
			return false;

		Asn1::CTS::_POD_PasswordPolicy policy = session->GetProfile()->get_passwordPolicy();

		_vars._session = session;
		_vars._minLen = policy.get_minLength();
		_vars._maxLen = policy.get_maxLength();

		//if (SUCCEEDED(session->QueryInterface(__uuidof(ICKMSessionSSO), (void**)&sso)))
		//	params.sso = sso;

		return true;
	}
	virtual tscrypto::tsCryptoString Pin() override
	{
		return _vars._pinBuffer;
	}
	virtual void Pin(const tscrypto::tsCryptoString& setTo) override
	{
		_vars._pinBuffer = setTo;
	}
protected:
	XP_WINDOW						 _parent;
	tokenLoginVariables              _vars;
};

tsmod::IObject* CreateTokenLogIn()
{
	return dynamic_cast<tsmod::IObject*>(new TokenLoginWrapper());
}