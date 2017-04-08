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

class HIDDEN EnterPinDlgWrapper : public IEnterPin, public tsmod::IObject
{
public:
	EnterPinDlgWrapper() :
		m_pParentWnd(nullptr),
		m_dlg(nullptr)
	{
		_vars.m_creatingPin = false;
		_vars.m_changingPin = false;
		_vars.minLen = 6;
		_vars.maxLen = 128;
		_vars.weakStrength = WEAK_PASSWORD_ENTROPY;
		_vars.strongStrength = STRONG_PASSWORD_ENTROPY;
		_vars.maxStrength = 100;
		_vars.helpId = 0;
		m_Explanation = "Please enter the password";
		m_StatusMsg = "";
		m_WindowTitle = "Password";
	}
	~EnterPinDlgWrapper()
	{
		Destroy();
	}

	virtual bool Destroy() override
	{
		return true;
	}
	virtual int   DisplayModal() override
	{
		std::shared_ptr<tsmod::IObject>	Me; // Keep me alive until Destroy is called

		if (m_pParentWnd == XP_WINDOW_INVALID)
			m_pParentWnd = (XP_WINDOW)wxTheApp->GetTopWindow();

		Me = _me.lock();
		_vars.DlgWrapper = std::dynamic_pointer_cast<IEnterPin>(Me);
		auto cleanup = finally([this]() {
			_vars.DlgWrapper.reset();
		});

		if (_vars.minLen > _vars.maxLen)
			_vars.maxLen = _vars.minLen;

		// Construct the dialog here
		EnterPin dlg;
		dlg.setVariables(&_vars);
		dlg.Create((wxWindow*)m_pParentWnd);
		dlg.SetTitle(m_WindowTitle.c_str());
		if (!m_Explanation.empty())
			dlg.setExplanation(m_Explanation.c_str());
		if (!m_StatusMsg.empty())
			dlg.setStatus(m_StatusMsg.c_str());
		dlg.setVariables(&_vars);

		m_dlg = &dlg;
		int retVal = dlg.ShowModal();
		m_dlg = nullptr;

		return retVal;
	}
	virtual int   DisplayModal(XP_WINDOW wnd) override
	{
		m_pParentWnd = wnd;
		return DisplayModal();
	}
	virtual void SetExplanation(const tscrypto::tsCryptoString & setTo) override
	{
		m_Explanation = setTo;
		if (m_dlg != nullptr)
		{
			m_dlg->setExplanation(setTo);
		}
	}
	virtual void SetStatus(const tscrypto::tsCryptoString & setTo) override
	{
		m_StatusMsg = setTo;
		if (m_dlg != nullptr)
		{
			m_dlg->setStatus(setTo);
		}
	}
	virtual void SetPinTesterFunction(std::function<bool(std::shared_ptr<IEnterPin>, const tscrypto::tsCryptoString&)> func) override
	{
		_vars.pinTesterFn = func;
	}
	virtual bool Start(const tscrypto::tsCryptoString & title, EnterPinMode mode, XP_WINDOW parent) override
	{
		_vars.m_creatingPin = false;
		_vars.m_changingPin = false;
		switch (mode)
		{
		case enterPin:
			break;
		case createPin:
			_vars.m_creatingPin = true;
			break;
		case changePin:
			_vars.m_changingPin = true;
			break;
		}
		m_WindowTitle = title;
		m_pParentWnd = parent;

		return false;
	}
	virtual tscrypto::tsCryptoString Pin() override
	{
		return _vars.m_pin;
	}
	virtual void Pin(const tscrypto::tsCryptoString & setTo) override
	{
		_vars.m_pin = setTo;
	}
	virtual void SetMinimumLength(uint32_t setTo) override
	{
		if (setTo > 3 && setTo < 128)
			_vars.minLen = setTo;
	}
	virtual void SetMaximumLength(uint32_t setTo) override
	{
		if (setTo > 3 && setTo < 128)
			_vars.maxLen = setTo;
	}
	virtual void SetPinStrengthFunction(std::function<int(std::shared_ptr<IEnterPin>, const tscrypto::tsCryptoString&)> func) override
	{
		_vars.pinStrengthFn = func;
	}
	virtual tscrypto::tsCryptoString OldPin() override
	{
		return _vars.m_oldPin;
	}
	virtual void OldPin(const tscrypto::tsCryptoString & setTo) override
	{
		_vars.m_oldPin = setTo;
	}
	virtual uint32_t GetWeakStrength() const override
	{
		return _vars.weakStrength;
	}
	virtual void SetWeakStrength(uint32_t setTo) override
	{
		_vars.weakStrength = setTo;
	}
	virtual uint32_t GetStrongStrength() const override
	{
		return _vars.strongStrength;
	}
	virtual void SetStrongStrength(uint32_t setTo) override
	{
		_vars.strongStrength = setTo;
	}
	virtual uint32_t GetMaxStrength() const override
	{
		return _vars.maxStrength;
	}
	virtual void SetMaxStrength(uint32_t setTo) override
	{
		_vars.maxStrength = setTo;
	}
	virtual void SetHelpId(uint32_t setTo) override
	{
		_vars.helpId = setTo;
	}


private:
	tscrypto::tsCryptoString m_Explanation;
	tscrypto::tsCryptoString m_StatusMsg;
	tscrypto::tsCryptoString m_WindowTitle;
	enterPinVariables _vars;
	XP_WINDOW m_pParentWnd;
	EnterPin* m_dlg;

};

tsmod::IObject* CreateEnterPinDlg()
{
	return dynamic_cast<tsmod::IObject*>(new EnterPinDlgWrapper());
}