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

class HIDDEN ChangeNameDlgWrapper : public IChangeName, public tsmod::IObject
{
public:
	ChangeNameDlgWrapper() :
		m_pParentWnd(nullptr)
	{
		m_Description = "Enter a new name.";
	}
	~ChangeNameDlgWrapper()
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

		// Construct the dialog here
		ChangeNameDlg dlg;

		dlg.helpId = helpid;
		dlg.Create((wxWindow*)m_pParentWnd);
		if (!m_Description.empty())
			dlg.SetDescription(m_Description.c_str());
		if (!m_OldName.empty())
			dlg.SetOldName(m_OldName.c_str());

		int retVal = dlg.ShowModal();

		m_NewName = dlg.GetNewName();

		return retVal;
	}
	virtual int   DisplayModal(XP_WINDOW wnd) override
	{
		m_pParentWnd = wnd;
		return DisplayModal();
	}

private:
	tscrypto::tsCryptoString m_Description;
	tscrypto::tsCryptoString m_OldName;
	tscrypto::tsCryptoString m_NewName;
	XP_WINDOW m_pParentWnd;
	uint32_t helpid;

	// Inherited via IChangeName
	virtual tscrypto::tsCryptoString Description() override
	{
		return m_Description;
	}
	virtual void Description(const tscrypto::tsCryptoString & setTo) override
	{
		m_Description = setTo;
	}
	virtual tscrypto::tsCryptoString OldName() override
	{
		return m_OldName;
	}
	virtual void OldName(const tscrypto::tsCryptoString & setTo) override
	{
		m_OldName = setTo;
	}
	virtual bool Start(XP_WINDOW parent, uint32_t helpId) override
	{
		m_pParentWnd = parent;
		helpid = helpId;
		return true;
	}
	virtual tscrypto::tsCryptoString NewName() override
	{
		return m_NewName;
	}
	virtual void NewName(const tscrypto::tsCryptoString & setTo) override
	{
		m_NewName = setTo;
	}
};

tsmod::IObject* CreateChangeName()
{
	return dynamic_cast<tsmod::IObject*>(new ChangeNameDlgWrapper());
}