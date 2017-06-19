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

// For compilers that support precompilation, includes "wx/wx.h".
#include "stdafx.h"

////@begin includes
////@end includes

////@begin XPM images
////@end XPM images


/*
 * KeyVEILWizardPage type definition
 */

IMPLEMENT_DYNAMIC_CLASS(KeyVEILWizardPage, wxWizardPageSimple)


/*
 * KeyVEILWizardPage event table definition
 */

	BEGIN_EVENT_TABLE(KeyVEILWizardPage, wxWizardPageSimple)

	////@begin KeyVEILWizardPage event table entries
    EVT_WIZARD_PAGE_CHANGED( -1, KeyVEILWizardPage::OnKeyveilLoginPageChanged )
    EVT_WIZARD_PAGE_CHANGING( -1, KeyVEILWizardPage::OnKeyveilLoginPageChanging )
    EVT_WIZARD_FINISHED( ID_KEYVEIL_LOGIN, KeyVEILWizardPage::OnKeyveilLoginFinished )
    EVT_WIZARD_HELP( -1, KeyVEILWizardPage::OnKeyveilLoginHelp )
    EVT_TEXT( ID_KEYVEIL_URL, KeyVEILWizardPage::OnKeyveilUrlTextUpdated )
    EVT_TEXT( ID_KEYVEIL_USER, KeyVEILWizardPage::OnKeyveilUserTextUpdated )
    EVT_TEXT( ID_KEYVEIL_PASSWORD, KeyVEILWizardPage::OnKeyveilPasswordTextUpdated )
    EVT_BUTTON( ID_CONNECT, KeyVEILWizardPage::OnConnectClick )
	////@end KeyVEILWizardPage event table entries

	END_EVENT_TABLE()


	/*
 * KeyVEILWizardPage constructors
 */

	KeyVEILWizardPage::KeyVEILWizardPage() : _initialized(false), nextPage(nullptr), prevPage(nullptr)
{
    Init();
}

KeyVEILWizardPage::KeyVEILWizardPage(wxWizard* parent) : _initialized(false), nextPage(nullptr), prevPage(nullptr)
{
    Init();
	Create(parent);
}


/*
 * KeyVEILWizardPage creator
 */

bool KeyVEILWizardPage::Create(wxWizard* parent)
{
	////@begin KeyVEILWizardPage creation
    SetExtraStyle(wxWS_EX_VALIDATE_RECURSIVELY);
    wxBitmap wizardBitmap(wxNullBitmap);
    wxWizardPage::Create( parent, wizardBitmap );

    CreateControls();
    if (GetSizer())
        GetSizer()->Fit(this);
	////@end KeyVEILWizardPage creation
    return true;
}


/*
 * KeyVEILWizardPage destructor
 */

KeyVEILWizardPage::~KeyVEILWizardPage()
{
	////@begin KeyVEILWizardPage destruction
	////@end KeyVEILWizardPage destruction
}


/*
 * Member initialisation
 */

void KeyVEILWizardPage::Init()
{
	////@begin KeyVEILWizardPage member initialisation
    _txtKeyVEILUrl = NULL;
    _txtUsername = NULL;
    _txtPassword = NULL;
    _btnConnect = NULL;
	////@end KeyVEILWizardPage member initialisation
}

/*
 * Control creation for KeyVEILWizardPage
 */

void KeyVEILWizardPage::CreateControls()
{    
	////@begin KeyVEILWizardPage content construction
    KeyVEILWizardPage* itemWizardPage1 = this;

    wxBoxSizer* itemBoxSizer2 = new wxBoxSizer(wxVERTICAL);
    itemWizardPage1->SetSizer(itemBoxSizer2);

    wxStaticText* itemStaticText3 = new wxStaticText( itemWizardPage1, wxID_STATIC, _("Connect to KeyVEIL"), wxDefaultPosition, wxDefaultSize, 0 );
    itemStaticText3->SetFont(wxFont(8, wxFONTFAMILY_SWISS, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_BOLD, false, wxT("Tahoma")));
    itemBoxSizer2->Add(itemStaticText3, 0, wxALIGN_LEFT|wxALL, 5);

    wxStaticText* itemStaticText4 = new wxStaticText( itemWizardPage1, wxID_STATIC, _("Enter the URL for KeyVEIL:"), wxDefaultPosition, wxDefaultSize, 0 );
    itemBoxSizer2->Add(itemStaticText4, 0, wxALIGN_LEFT|wxALL, 5);

    _txtKeyVEILUrl = new wxTextCtrl( itemWizardPage1, ID_KEYVEIL_URL, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
    _txtKeyVEILUrl->SetMaxLength(512);
    if (KeyVEILWizardPage::ShowToolTips())
        _txtKeyVEILUrl->SetToolTip(_("Enter the URL of the VEIL or KeyVEIL that is to be used."));
    itemBoxSizer2->Add(_txtKeyVEILUrl, 0, wxGROW|wxALL, 5);

    wxStaticText* itemStaticText6 = new wxStaticText( itemWizardPage1, wxID_STATIC, _("Enter the user name:"), wxDefaultPosition, wxDefaultSize, 0 );
    itemBoxSizer2->Add(itemStaticText6, 0, wxALIGN_LEFT|wxALL, 5);

    _txtUsername = new wxTextCtrl( itemWizardPage1, ID_KEYVEIL_USER, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
    if (KeyVEILWizardPage::ShowToolTips())
        _txtUsername->SetToolTip(_("Enter the username for that VEIL/KeyVEIL"));
    itemBoxSizer2->Add(_txtUsername, 0, wxGROW|wxALL, 5);

    wxStaticText* itemStaticText8 = new wxStaticText( itemWizardPage1, wxID_STATIC, _("Enter the user password:"), wxDefaultPosition, wxDefaultSize, 0 );
    itemBoxSizer2->Add(itemStaticText8, 0, wxALIGN_LEFT|wxALL, 5);

    _txtPassword = new wxTextCtrl( itemWizardPage1, ID_KEYVEIL_PASSWORD, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_PASSWORD );
    if (KeyVEILWizardPage::ShowToolTips())
        _txtPassword->SetToolTip(_("Enter the user's password."));
    itemBoxSizer2->Add(_txtPassword, 0, wxGROW|wxALL, 5);

    itemBoxSizer2->Add(5, 5, 0, wxALIGN_CENTER_HORIZONTAL|wxALL, 5);

    wxFlexGridSizer* itemFlexGridSizer11 = new wxFlexGridSizer(1, 3, 0, 0);
    itemBoxSizer2->Add(itemFlexGridSizer11, 0, wxGROW|wxALL, 5);

    _btnConnect = new wxButton( itemWizardPage1, ID_CONNECT, _("Connect"), wxDefaultPosition, wxDefaultSize, 0 );
    if (KeyVEILWizardPage::ShowToolTips())
        _btnConnect->SetToolTip(_("Attempt to connect to the VEIL/KeyVEIL."));
    itemFlexGridSizer11->Add(_btnConnect, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    itemFlexGridSizer11->AddGrowableCol(0);
    itemFlexGridSizer11->AddGrowableCol(2);

	////@end KeyVEILWizardPage content construction
	updateControls();
}


/*
 * wxEVT_WIZARD_PAGE_CHANGED event handler for ID_KEYVEIL_LOGIN
 */

void KeyVEILWizardPage::OnKeyveilLoginPageChanged(wxWizardEvent& event)
{
	if (!_initialized)
	{
		std::shared_ptr<BasicVEILPreferences> prefs = BasicVEILPreferences::Create();

		prefs->loadValues();

		_initialized = true;

		if (_url.size() == 0)
		{
			_url = prefs->getKeyVEILUrl();
		}
		if (_username.empty())
		{
			_username = prefs->getKeyVEILUsername();
		}

		AudienceSelector2* wiz = dynamic_cast<AudienceSelector2*>(GetParent());

			_txtKeyVEILUrl->SetValue(_url.c_str());
			_txtUsername->SetValue(_username.c_str());
		if (wiz != nullptr && wiz->_vars != nullptr && wiz->_vars->_connector->isConnected())
		{
			//EndDialog(wxID_OK);
		}
		if (_url.size() > 0)
		{
			if (!_username.empty())
			{
				_txtPassword->SetFocus();
			}
			else
			{
				_txtUsername->SetFocus();
			}
		}
	}
	updateControls();
    event.Skip();
}


/*
 * wxEVT_WIZARD_PAGE_CHANGING event handler for ID_KEYVEIL_LOGIN
 */

void KeyVEILWizardPage::OnKeyveilLoginPageChanging(wxWizardEvent& event)
{
    event.Skip();
}


/*
 * wxEVT_WIZARD_FINISHED event handler for ID_KEYVEIL_LOGIN
 */

void KeyVEILWizardPage::OnKeyveilLoginFinished(wxWizardEvent& event)
{
	////@begin wxEVT_WIZARD_FINISHED event handler for ID_KEYVEIL_LOGIN in KeyVEILWizardPage.
    // Before editing this code, remove the block markers.
    event.Skip();
	////@end wxEVT_WIZARD_FINISHED event handler for ID_KEYVEIL_LOGIN in KeyVEILWizardPage. 
}


/*
 * wxEVT_WIZARD_HELP event handler for ID_KEYVEIL_LOGIN
 */

void KeyVEILWizardPage::OnKeyveilLoginHelp(wxWizardEvent& event)
{
	std::shared_ptr<IVEILHttpHelpRegistry> help = ::TopServiceLocator()->get_instance<IVEILHttpHelpRegistry>("/WxWin/HelpRegistry");
	AudienceSelector2* wiz = dynamic_cast<AudienceSelector2*>(GetParent());

	if (!help)
	{
		wxTsMessageBox(("Help is not available at this time."), ("Status"), wxOK);
	}
	else
	{
		if (wiz != nullptr && wiz->_vars != nullptr && wiz->_vars->_favoriteId != GUID_NULL)
		{
			help->DisplayHelpForWindowId(winid_FavEdit_KeyVEILLoginPage, (XP_WINDOW)this);
		}
		else if (wiz != nullptr && wiz->_vars != nullptr && wiz->_vars->_favoriteManager)
		{
			help->DisplayHelpForWindowId(winid_FavAdd_KeyVEILLoginPage, (XP_WINDOW)this);
		}
		else
		help->DisplayHelpForWindowId(winid_KeyVEILLoginPage, (XP_WINDOW)this);
	}
}


/*
 * wxEVT_COMMAND_TEXT_UPDATED event handler for ID_KEYVEIL_URL
 */

void KeyVEILWizardPage::OnKeyveilUrlTextUpdated(wxCommandEvent& event)
{
	updateControls();
}


/*
 * wxEVT_COMMAND_TEXT_UPDATED event handler for ID_KEYVEIL_USER
 */

void KeyVEILWizardPage::OnKeyveilUserTextUpdated(wxCommandEvent& event)
{
	updateControls();
}


/*
 * wxEVT_COMMAND_TEXT_UPDATED event handler for ID_KEYVEIL_PASSWORD
 */

void KeyVEILWizardPage::OnKeyveilPasswordTextUpdated(wxCommandEvent& event)
{
	updateControls();
}


/*
 * Should we show tooltips?
 */

bool KeyVEILWizardPage::ShowToolTips()
{
    return true;
}

/*
 * Get bitmap resources
 */

wxBitmap KeyVEILWizardPage::GetBitmapResource(const wxString& name)
{
	return ::GetBitmapResource(name);
}

/*
 * Get icon resources
 */

wxIcon KeyVEILWizardPage::GetIconResource(const wxString& name)
{
    // Icon retrieval
////@begin KeyVEILWizardPage icon retrieval
    wxUnusedVar(name);
    return wxNullIcon;
	////@end KeyVEILWizardPage icon retrieval
}


/*
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_CONNECT
 */

void KeyVEILWizardPage::OnConnectClick(wxCommandEvent& event)
{
	tsCryptoString password;
	AudienceSelector2* wiz = dynamic_cast<AudienceSelector2*>(GetParent());

	if (wiz == nullptr || wiz->_vars == nullptr || !wiz->_vars->_connector)
	{
		wxTsMessageBox("Internal Error - No connector.", "ERROR", wxICON_HAND | wxOK, (XP_WINDOW)this);
		return;
	}

	_url = _txtKeyVEILUrl->GetValue().mbc_str().data();
	_username = _txtUsername->GetValue().mbc_str().data();
	password = _txtPassword->GetValue().mbc_str().data();

	if (_url.Trim().empty() || _username.Trim().empty())
		password.clear();

	if (!password.empty())
		wiz->_vars->_connector->disconnect();

	wxBusyCursor busyCursor;
	wxWindowDisabler disabler;
	wxBusyInfo busyInfo(_("Connecting to KeyVEIL..."));

	if ((!wiz->_vars->_connector->isConnected() || wiz->_vars->_connector->errorCode() == 401 || wiz->_vars->_connector->errorCode() == 440) && !password.empty())
	{
		ConnectionStatus status = wiz->_vars->_connector->connect(_url, _username, password);

		switch (status)
		{
		case connStatus_Connected:
		{
			std::shared_ptr<BasicVEILPreferences> prefs = BasicVEILPreferences::Create();

			prefs->loadValues();

			if (prefs->getKeyVEILUrl().empty() || prefs->getKeyVEILUsername().empty())
			{
				 prefs->setKeyVEILUrl(_url);
				 prefs->setKeyVEILUsername(_username);
				 prefs->saveConfigurationChanges();
			}

			_txtPassword->SetValue("");
			updateControls();
			((wxWizard*)this->GetParent())->ShowPage(GetNext());
		}
			return;
		case connStatus_NoServer:
			wxTsMessageBox("The KeyVEIL server was not found.", "ERROR", wxICON_HAND | wxOK, (XP_WINDOW)this);
			return;
		case connStatus_BadAuth:
			wxTsMessageBox("The specified username or password is invalid.", "ERROR", wxICON_HAND | wxOK, (XP_WINDOW)this);
			return;
		case connStatus_WrongProtocol:
			wxTsMessageBox("The specified protocol is not supported.", "ERROR", wxICON_HAND | wxOK, (XP_WINDOW)this);
			return;
		case connStatus_UrlBad:
			wxTsMessageBox("The specified url is invalid.", "ERROR", wxICON_HAND | wxOK, (XP_WINDOW)this);
			return;
		default:
			wxTsMessageBox("An unknown error has occurred.", "ERROR", wxICON_HAND | wxOK, (XP_WINDOW)this);
			return;
		}
	}
	if (!wiz->_vars->_connector->isConnected() || wiz->_vars->_connector->errorCode() == 401 || wiz->_vars->_connector->errorCode() == 440)
	{
		wxTsMessageBox("The specified KeyVEIL is not available.", "ERROR", wxICON_HAND | wxOK, (XP_WINDOW)this);
	}
	updateControls();
}

void KeyVEILWizardPage::updateControls()
{
	AudienceSelector2* wiz = dynamic_cast<AudienceSelector2*>(GetParent());

	if (wiz == nullptr || wiz->_vars == nullptr || !wiz->_vars->_connector)
	{
		FindWindowById(wxID_FORWARD, this->GetParent())->Enable(false);
		return;
	}

	tsCryptoString password = _txtPassword->GetValue().mbc_str().data();
	tsCryptoString url = _txtKeyVEILUrl->GetValue().mbc_str().data();
	tsCryptoString username = _txtUsername->GetValue().mbc_str().data();
	if (url.Trim().empty() || username.Trim().empty())
		password.clear();

	_btnConnect->Enable(!password.empty() && !url.empty() && !username.empty());
	if (!password.empty() && !url.empty() && !username.empty())
		_btnConnect->SetDefault();
	else
		((wxButton*)FindWindowById(wxID_FORWARD, this->GetParent()))->SetDefault();

	if ((!wiz->_vars->_connector->isConnected() || wiz->_vars->_connector->errorCode() == 401 || wiz->_vars->_connector->errorCode() == 440))
	{
		FindWindowById(wxID_FORWARD, this->GetParent())->Enable(false);
	}
	else
	{
		FindWindowById(wxID_FORWARD, this->GetParent())->Enable(true);
	}
	//FindWindowById(wxID_BACKWARD, this->GetParent())->Enable(false);
}

bool KeyVEILWizardPage::skipMe()
{
	AudienceSelector2* wiz = dynamic_cast<AudienceSelector2*>(GetParent());

	if (wiz == nullptr || wiz->_vars == nullptr)
		return false;

	return wiz->_vars->_hideKeyVEILLogin;
}


/*
 * Gets the previous page.
 */

wxWizardPage* KeyVEILWizardPage::GetPrev() const
{
	ISkippablePage* tokPg = dynamic_cast<ISkippablePage*>(prevPage);

	if (tokPg != nullptr && tokPg->skipMe())
		return prevPage->GetPrev();
    return prevPage;
}


/*
 * Gets the next page.
 */

wxWizardPage* KeyVEILWizardPage::GetNext() const
{
	ISkippablePage* tokPg = dynamic_cast<ISkippablePage*>(nextPage);

	if (tokPg != nullptr && tokPg->skipMe())
		return nextPage->GetNext();
    return nextPage;
}

