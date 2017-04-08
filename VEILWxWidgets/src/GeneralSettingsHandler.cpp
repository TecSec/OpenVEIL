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

class GeneralSettingsHandler : public IVEILPropertyPage, public tsmod::IObject
{
public:
	GeneralSettingsHandler() : 
		_parent(nullptr)
	{
	}
	virtual ~GeneralSettingsHandler() {}

	// wxPanel
	virtual bool Destroy() override
	{
		if (_parent != XP_WINDOW_INVALID)
			((wxWindow*)_parent)->RemoveChild(&_dlg);
		_parent = XP_WINDOW_INVALID;
		_dlg._parentSheet.reset();
		Me.reset();
		return true;
	}

	// Inherited via IVEILPropertyPage
	virtual tscrypto::tsCryptoString Title() const override
	{
		return "General";
	}
	virtual void SetParent(std::shared_ptr<IVEILPropertySheet> parentSheet) override
	{
		_dlg._parentSheet = parentSheet;

		if (!!parentSheet)
		{
			_dlg._prefs = parentSheet->BasicPreferences();
		}
	}
	virtual XP_WINDOW CreatePage(XP_WINDOW parentWindow) override
	{
		// Construct the dialog here
		_dlg.Create((wxWindow*)parentWindow);
		Me = std::dynamic_pointer_cast<GeneralSettingsHandler>(_me.lock());

		return (XP_WINDOW)(&_dlg);
	}

	virtual void OnHelp() override
	{
		std::shared_ptr<IVEILHttpHelpRegistry> help = ::TopServiceLocator()->get_instance<IVEILHttpHelpRegistry>("/WxWin/HelpRegistry");

		if (!help)
		{
			wxTsMessageBox(("Help is not available at this time."), ("Status"), wxOK);
		}
		else
		{
			help->DisplayHelpForWindowId(winid_GeneralSettings, (XP_WINDOW)&_dlg);
		}
	}
	virtual PPResult Apply() override
	{
		// Get the values from the dialog
		_dlg.UpdateData(true);
		// Get the values of the controls

		if (_dlg._prefs->EncryptionAlgorithmLocation() != jc_Policy)
			_dlg._prefs->setEncryptionAlgorithm(_dlg._Alg);
		if (_dlg._prefs->HashAlgorithmLocation() != jc_Policy)
			_dlg._prefs->setHashAlgorithm(_dlg._HashAlg);
		if (_dlg._prefs->KeyVEILUrlLocation() != jc_Policy)
			_dlg._prefs->setKeyVEILUrl(_dlg._url);
		if (_dlg._prefs->KeyVEILUsernameLocation() != jc_Policy)
			_dlg._prefs->setKeyVEILUsername(_dlg._username);
		if (_dlg._prefs->AIDListLocation() != jc_Policy)
			_dlg._prefs->setAIDList(_dlg._aidList);

		_dlg._prefs->saveConfigurationChanges();

		_dlg.UpdateData(false);

		_dlg.SetModified(false);
		return NoError;
	}
	virtual bool KillActive() override
	{
		// Validate controls
		return false;
	}
	virtual bool QueryCancel() override
	{
		return false;
	}
	virtual bool QueryInitialFocus() override
	{
		return false;
	}
	virtual bool Reset() override
	{
		return false;
	}
	virtual bool SetActive() override
	{
		return false;
	}

protected:
	XP_WINDOW  _parent;
	std::shared_ptr<GeneralSettingsHandler> Me; // Keep me alive until Destroy is called
	GeneralSettingsPropertyPage _dlg;
};

tsmod::IObject* CreateGeneralSettingsPage()
{
	return dynamic_cast<tsmod::IObject*>(new GeneralSettingsHandler());
}