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
 * TokenSelectionWizardPage type definition
 */

IMPLEMENT_DYNAMIC_CLASS(TokenSelectionWizardPage, wxWizardPageSimple)


/*
 * TokenSelectionWizardPage event table definition
 */

    BEGIN_EVENT_TABLE(TokenSelectionWizardPage, wxWizardPageSimple)

    ////@begin TokenSelectionWizardPage event table entries
    EVT_WIZARD_PAGE_CHANGED( -1, TokenSelectionWizardPage::OnSelectTokenPageChanged )
    EVT_WIZARD_PAGE_CHANGING( -1, TokenSelectionWizardPage::OnSelectTokenPageChanging )
    EVT_WIZARD_FINISHED( ID_SELECT_TOKEN, TokenSelectionWizardPage::OnSelectTokenFinished )
    EVT_WIZARD_HELP( -1, TokenSelectionWizardPage::OnSelectTokenHelp )
    EVT_CHOICE( ID_TOKEN, TokenSelectionWizardPage::OnTokenSelected )
    EVT_TEXT( ID_TOKEN_PASSWORD, TokenSelectionWizardPage::OnTokenPasswordTextUpdated )
    EVT_BUTTON( ID_TOKEN_LOGIN, TokenSelectionWizardPage::OnTokenLoginClick )
    ////@end TokenSelectionWizardPage event table entries

    END_EVENT_TABLE()


    /*
     * TokenSelectionWizardPage constructors
     */

    TokenSelectionWizardPage::TokenSelectionWizardPage() : nextPage(nullptr), prevPage(nullptr)
{
    Init();
}

TokenSelectionWizardPage::TokenSelectionWizardPage(wxWizard* parent) : nextPage(nullptr), prevPage(nullptr)
{
    Init();
    Create(parent);
}


/*
 * TokenSelectionWizardPage creator
 */

bool TokenSelectionWizardPage::Create(wxWizard* parent)
{
    ////@begin TokenSelectionWizardPage creation
    SetExtraStyle(wxWS_EX_VALIDATE_RECURSIVELY);
    wxBitmap wizardBitmap(wxNullBitmap);
    wxWizardPage::Create( parent, wizardBitmap );

    CreateControls();
    if (GetSizer())
        GetSizer()->Fit(this);
    ////@end TokenSelectionWizardPage creation
    updateControls();
    return true;
}


/*
 * TokenSelectionWizardPage destructor
 */

TokenSelectionWizardPage::~TokenSelectionWizardPage()
{
    ////@begin TokenSelectionWizardPage destruction
    ////@end TokenSelectionWizardPage destruction
}


/*
 * Member initialisation
 */

void TokenSelectionWizardPage::Init()
{
    ////@begin TokenSelectionWizardPage member initialisation
    _cmbToken = NULL;
    lblTokenPassword = NULL;
    _txtTokenPassword = NULL;
    _btnTokenLogin = NULL;
    ////@end TokenSelectionWizardPage member initialisation
}


/*
 * Control creation for TokenSelectionWizardPage
 */

void TokenSelectionWizardPage::CreateControls()
{
    ////@begin TokenSelectionWizardPage content construction
    TokenSelectionWizardPage* itemWizardPage1 = this;

    wxBoxSizer* itemBoxSizer2 = new wxBoxSizer(wxVERTICAL);
    itemWizardPage1->SetSizer(itemBoxSizer2);

    wxStaticText* itemStaticText3 = new wxStaticText( itemWizardPage1, wxID_STATIC, _("Select Token"), wxDefaultPosition, wxDefaultSize, 0 );
    itemStaticText3->SetFont(wxFont(8, wxFONTFAMILY_SWISS, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_BOLD, false, wxT("Tahoma")));
    itemBoxSizer2->Add(itemStaticText3, 0, wxALIGN_LEFT|wxALL, 5);

    itemBoxSizer2->Add(5, 5, 0, wxALIGN_CENTER_HORIZONTAL|wxALL, 5);

    wxStaticText* itemStaticText5 = new wxStaticText( itemWizardPage1, wxID_STATIC, _("Token name:"), wxDefaultPosition, wxDefaultSize, 0 );
    itemBoxSizer2->Add(itemStaticText5, 0, wxALIGN_LEFT|wxALL, 5);

    wxArrayString _cmbTokenStrings;
    _cmbToken = new wxChoice( itemWizardPage1, ID_TOKEN, wxDefaultPosition, wxDefaultSize, _cmbTokenStrings, 0 );
    if (TokenSelectionWizardPage::ShowToolTips())
        _cmbToken->SetToolTip(_("Select the token that is to be used for this encryption."));
    itemBoxSizer2->Add(_cmbToken, 0, wxGROW|wxALL, 5);

    lblTokenPassword = new wxStaticText( itemWizardPage1, wxID_STATIC, _("Token Password:"), wxDefaultPosition, wxDefaultSize, 0 );
    itemBoxSizer2->Add(lblTokenPassword, 0, wxGROW|wxALL, 5);

    _txtTokenPassword = new wxTextCtrl( itemWizardPage1, ID_TOKEN_PASSWORD, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_PASSWORD );
    _txtTokenPassword->SetMaxLength(128);
    if (TokenSelectionWizardPage::ShowToolTips())
        _txtTokenPassword->SetToolTip(_("Enter the password for this token."));
    itemBoxSizer2->Add(_txtTokenPassword, 0, wxGROW|wxALL, 5);

    itemBoxSizer2->Add(5, 5, 0, wxALIGN_CENTER_HORIZONTAL|wxALL, 5);

    _btnTokenLogin = new wxButton( itemWizardPage1, ID_TOKEN_LOGIN, _("Login"), wxDefaultPosition, wxDefaultSize, 0 );
    _btnTokenLogin->SetDefault();
    if (TokenSelectionWizardPage::ShowToolTips())
        _btnTokenLogin->SetToolTip(_("Attempt to log into the token."));
    _btnTokenLogin->Enable(false);
    itemBoxSizer2->Add(_btnTokenLogin, 0, wxALIGN_CENTER_HORIZONTAL|wxALL, 5);

    ////@end TokenSelectionWizardPage content construction
}


/*
 * wxEVT_WIZARD_PAGE_CHANGED event handler for ID_SELECT_TOKEN
 */

void TokenSelectionWizardPage::OnSelectTokenPageChanged(wxWizardEvent& event)
{
    AudienceSelector2* wiz = dynamic_cast<AudienceSelector2*>(GetParent());

    _cmbToken->Clear();

    if (wiz != nullptr && wiz->_vars != nullptr && !!wiz->_vars->_connector)
    {
        size_t count = wiz->_vars->_connector->tokenCount();

        for (size_t i = 0; i < count; i++)
        {
            std::shared_ptr<IToken> tok = wiz->_vars->_connector->token(i);
            if (!!tok)
            {
                _cmbToken->AppendString(tok->tokenName().c_str());
            }
        }
        if (!_tokenName.empty())
        {
            _cmbToken->SetSelection(_cmbToken->FindString(_tokenName.c_str()));

        }
        else if (_cmbToken->GetCount() == 1)
        {
            _cmbToken->SetSelection(0);
            _txtTokenPassword->Enable(true);
            _txtTokenPassword->SetFocus();
        }
        else
            _cmbToken->SetSelection(-1);

        int sel = _cmbToken->GetSelection();
        if (sel >= 0)
        {
            _tokenName = _cmbToken->GetString(sel).mbc_str().data();
            wiz->_vars->_token = wiz->_vars->_connector->token(_tokenName);
            if (!wiz->_vars->_token)
            {
                _cmbToken->SetSelection(-1);
            }
            else
            {
				if (!!wiz->_vars->_session && !!!wiz->_vars->_session->HasProfile())
				{
					wxBusyCursor busyCursor;
					wxWindowDisabler disabler;
					wxBusyInfo busyInfo(_("Retrieving token information..."));

                    wiz->_vars->_session->GetProfile();
				}

                if (!!wiz->_vars->_session && !!wiz->_vars->_session->GetProfile() && wiz->_vars->_session->GetProfile()->exists_SerialNumber() &&
                    *wiz->_vars->_session->GetProfile()->get_SerialNumber() == wiz->_vars->_token->serialNumber())
                {

                }
                else
                {
                    wiz->_vars->_session = wiz->_vars->_token->openSession();
                }
            }
        }
        else
        {
            _tokenName.clear();
            wiz->_vars->_session.reset();
            wiz->_vars->_token.reset();
        }
    }
    else if (wiz != nullptr && wiz->_vars != nullptr)
    {
        wiz->_vars->_token.reset();
        wiz->_vars->_session.reset();
    }
#ifdef __APPLE__
    if (_txtTokenPassword->IsEnabled())
        _txtTokenPassword->SetFocus();
#endif __APPLE__
    Layout();
    updateControls();
    event.Skip();
}


/*
 * wxEVT_WIZARD_PAGE_CHANGING event handler for ID_SELECT_TOKEN
 */

void TokenSelectionWizardPage::OnSelectTokenPageChanging(wxWizardEvent& event)
{
    event.Skip();
}


/*
 * wxEVT_WIZARD_FINISHED event handler for ID_SELECT_TOKEN
 */

void TokenSelectionWizardPage::OnSelectTokenFinished(wxWizardEvent& event)
{
    ////@begin wxEVT_WIZARD_FINISHED event handler for ID_SELECT_TOKEN in TokenSelectionWizardPage.
        // Before editing this code, remove the block markers.
    event.Skip();
    ////@end wxEVT_WIZARD_FINISHED event handler for ID_SELECT_TOKEN in TokenSelectionWizardPage. 
}


/*
 * wxEVT_WIZARD_HELP event handler for ID_SELECT_TOKEN
 */

void TokenSelectionWizardPage::OnSelectTokenHelp(wxWizardEvent& event)
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
            help->DisplayHelpForWindowId(winid_FavEdit_TokenSelectionPage, (XP_WINDOW)this);
        }
        else if (wiz != nullptr && wiz->_vars != nullptr && wiz->_vars->_favoriteManager)
        {
            help->DisplayHelpForWindowId(winid_FavAdd_TokenSelectionPage, (XP_WINDOW)this);
        }
        else
            help->DisplayHelpForWindowId(winid_TokenSelectionPage, (XP_WINDOW)this);
    }
}


/*
 * wxEVT_COMMAND_CHOICE_SELECTED event handler for ID_TOKEN
 */

void TokenSelectionWizardPage::OnTokenSelected(wxCommandEvent& event)
{
    AudienceSelector2* wiz = dynamic_cast<AudienceSelector2*>(GetParent());

    if (wiz == nullptr || wiz->_vars == nullptr || !wiz->_vars->_connector || !wiz->_vars->_connector->isConnected())
    {
        if (wiz != nullptr && wiz->_vars != nullptr)
        {
            wiz->_vars->_token.reset();
            wiz->_vars->_session.reset();
        }
        _tokenName.clear();
        wxTsMessageBox("The KeyVEIL server is no longer connected.", "ERROR", wxICON_HAND | wxOK, (XP_WINDOW)this);
        return;
    }
    _tokenName.clear();
    wiz->_vars->_token.reset();
    wiz->_vars->_session.reset();
    if (_cmbToken->GetSelection() < 0)
    {
        updateControls();
        return;
    }

    wxBusyCursor busyCursor;
    wxWindowDisabler disabler;
    wxBusyInfo busyInfo(_("Retrieving token information..."));

    wiz->_vars->_token = wiz->_vars->_connector->token(event.GetString().mbc_str().data());
    _tokenName = event.GetString().mbc_str().data();
    if (!wiz->_vars->_token)
    {
        wxTsMessageBox("The selected token appears to not be available.  Please select a different token.", "ERROR", wxICON_HAND | wxOK, (XP_WINDOW)this);
        return;
    }
    wiz->_vars->_session = wiz->_vars->_token->openSession();
    if (!wiz->_vars->_session)
    {
        wxTsMessageBox("The selected token appears to not be available.  Please select a different token.", "ERROR", wxICON_HAND | wxOK, (XP_WINDOW)this);
        return;
    }
    if (wiz->_vars->_session->IsLocked())
    {
        wxTsMessageBox("The selected token appears to be locked.  Please select a different token.", "ERROR", wxICON_HAND | wxOK, (XP_WINDOW)this);
        return;
    }
    // _txtTokenPassword->Enable(!wiz->_vars->_session->IsLoggedIn());
    _txtTokenPassword->SetValue("");
    updateControls();
}


/*
 * wxEVT_COMMAND_TEXT_UPDATED event handler for ID_TOKEN_PASSWORD
 */

void TokenSelectionWizardPage::OnTokenPasswordTextUpdated(wxCommandEvent& event)
{
    updateControls();
}


/*
 * Should we show tooltips?
 */

bool TokenSelectionWizardPage::ShowToolTips()
{
    return true;
}

/*
 * Get bitmap resources
 */

wxBitmap TokenSelectionWizardPage::GetBitmapResource(const wxString& name)
{
    return ::GetBitmapResource(name);
}

/*
 * Get icon resources
 */

wxIcon TokenSelectionWizardPage::GetIconResource(const wxString& name)
{
    // Icon retrieval
////@begin TokenSelectionWizardPage icon retrieval
    wxUnusedVar(name);
    return wxNullIcon;
    ////@end TokenSelectionWizardPage icon retrieval
}

void TokenSelectionWizardPage::updateControls()
{
    AudienceSelector2* wiz = dynamic_cast<AudienceSelector2*>(GetParent());

    if (wiz == nullptr || wiz->_vars == nullptr || !wiz->_vars->_connector || !wiz->_vars->_connector->isConnected())
    {
        FindWindowById(wxID_FORWARD, this->GetParent())->Enable(false);
        return;
    }

    //_txtTokenPassword->Enable(_cmbToken->GetSelection() >= 0);
    //_btnTokenLogin->Enable(_txtTokenPassword->GetValue().size() > 0);
    
    if (!!wiz->_vars->_session && !wiz->_vars->_session->IsLoggedIn())
    {
        _txtTokenPassword->Show(true);
        _btnTokenLogin->Show(true);
        lblTokenPassword->Show(true);
		_txtTokenPassword->Enable(_cmbToken->GetSelection() >= 0);
		_btnTokenLogin->Enable(_txtTokenPassword->GetValue().size() > 0);
        Layout();
    }
    else
    {
        _txtTokenPassword->Show(false);
        _btnTokenLogin->Show(false);
        lblTokenPassword->Show(false);
        Layout();
    }

    if (_txtTokenPassword->GetValue().size() > 0)
        _btnTokenLogin->SetDefault();
    else
        ((wxButton*)FindWindowById(wxID_FORWARD, this->GetParent()))->SetDefault();

    if (!wiz->_vars->_session)
    {
        FindWindowById(wxID_FORWARD, this->GetParent())->Enable(false);
    }
    else
    {
        FindWindowById(wxID_FORWARD, this->GetParent())->Enable(wiz->_vars->_session->IsLoggedIn());
    }
    //tsCryptoString password = _txtPassword->GetValue().mbc_str().data();
    //tsCryptoString url = _txtKeyVEILUrl->GetValue().mbc_str().data();
    //tsCryptoString username = _txtUsername->GetValue().mbc_str().data();
    //if (url.Trim().empty() || username.Trim().empty())
    //	password.clear();

    //_btnConnect->Enable(!password.empty() && !url.empty() && !username.empty());

    //if ((!wiz->_vars->_connector->isConnected() || wiz->_vars->_connector->errorCode() == 401 || wiz->_vars->_connector->errorCode() == 440))
    //{
    //	FindWindowById(wxID_FORWARD, this->GetParent())->Enable(false);
    //}
    //else
    //{
    //	FindWindowById(wxID_FORWARD, this->GetParent())->Enable(true);
    //}
    ////FindWindowById(wxID_BACKWARD, this->GetParent())->Enable(false);
}


/*
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_TOKEN_LOGIN
 */

void TokenSelectionWizardPage::OnTokenLoginClick(wxCommandEvent& event)
{
    tsCryptoString password;
    AudienceSelector2* wiz = dynamic_cast<AudienceSelector2*>(GetParent());
    GUID entID = GUID_NULL;


    if (wiz == nullptr || wiz->_vars == nullptr || !wiz->_vars->_connector || !wiz->_vars->_connector->isConnected())
    {
        wxTsMessageBox("The KeyVEIL server is no longer connected.", "ERROR", wxICON_HAND | wxOK, (XP_WINDOW)this);
        return;
    }
    if ((_cmbToken->GetSelection() < 0 || !wiz->_vars->_token))
    {
        wiz->_vars->_session.reset();
        _txtTokenPassword->SetValue("");
        updateControls();
        return;
    }
    if (_cmbToken->GetSelection() < 0 || !wiz->_vars->_token)
    {
        wiz->_vars->_session.reset();
        wxTsMessageBox("You must select a token before proceeding.", "ERROR", wxICON_HAND | wxOK, (XP_WINDOW)this);
        _txtTokenPassword->SetValue("");
        updateControls();
        return;
    }
    if (!!wiz->_vars->_session &&
        (!wiz->_vars->_token || !wiz->_vars->_session->GetProfile() || !wiz->_vars->_session->GetProfile()->exists_SerialNumber() || *wiz->_vars->_session->GetProfile()->get_SerialNumber() != wiz->_vars->_token->serialNumber()))
    {
        wiz->_vars->_session.reset();
        wiz->_vars->_session = wiz->_vars->_token->openSession();
    }
    else
        wiz->_vars->_session = wiz->_vars->_token->openSession();

    if (!wiz->_vars->_session)
    {
        wxTsMessageBox("The selected token appears to not be available.  Please select a different token.", "ERROR", wxICON_HAND | wxOK, (XP_WINDOW)this);
        return;
    }
    password = _txtTokenPassword->GetValue().mbc_str().data();
    if (!password.empty())
    {
        if (wiz->_vars->_session->IsLoggedIn())
            wiz->_vars->_session->Logout();
        if (!!wiz->_vars->_session)
        {
            LoginStatus status = wiz->_vars->_session->Login(password);

            switch (status)
            {
            case loginStatus_Connected:
                _txtTokenPassword->SetValue("");
                updateControls();
                
                entID = GUID_NULL;
                {
                    wxBusyCursor busyCursor;
                    wxWindowDisabler disabler;
                    wxBusyInfo busyInfo(_("Retrieving token information..."));

                    wiz->_vars->_session->GetProfile();
                    if (!!wiz->_vars->_session->GetProfile())
                        entID = wiz->_vars->_session->GetProfile()->get_EnterpriseId();
                }

                //if (wiz->_vars->_connector->favoriteCountForEnterprise(entID) == 0)
                //{
                //    SetNextPage(wiz->_accessGroupPage);
                //    wiz->_accessGroupPage->SetPrevPage(this);
                //}
                //else if (wiz->_vars->_favoriteManager)
                //{
                //    SetNextPage(wiz->_accessGroupPage);
                //    wiz->_accessGroupPage->SetPrevPage(this);
                //}
                //else
                //{
                //    SetNextPage(wiz->_favoriteSelectionPage);
                //    wiz->_favoriteSelectionPage->SetPrevPage(this);
                //}
                ((wxWizard*)this->GetParent())->ShowPage(GetNext());
                return;
            case loginStatus_NoServer:
                wxTsMessageBox("It appears that the KeyVEIL is no longer available.", "ERROR", wxICON_HAND | wxOK, (XP_WINDOW)this);
                return;
            case loginStatus_BadAuth:
            default:
                if (wiz->_vars->_session->IsLocked())
                {
                    wxTsMessageBox("The specified token is currently locked.", "ERROR", wxICON_HAND | wxOK, (XP_WINDOW)this);
                }
                else
                {
                    wxTsMessageBox("The specified login information is invalid.", "ERROR", wxICON_HAND | wxOK, (XP_WINDOW)this);
                }
                _txtTokenPassword->SetValue("");
                return;
            }
        }
    }
    _txtTokenPassword->SetValue("");
    updateControls();
}


/*
 * Gets the previous page.
 */

wxWizardPage* TokenSelectionWizardPage::GetPrev() const
{
	ISkippablePage* tokPg = dynamic_cast<ISkippablePage*>(prevPage);

	if (tokPg != nullptr && tokPg->skipMe())
		return prevPage->GetPrev();
	return prevPage;
}


/*
 * Gets the next page.
 */

wxWizardPage* TokenSelectionWizardPage::GetNext() const
{
	ISkippablePage* tokPg = dynamic_cast<ISkippablePage*>(nextPage);

	if (tokPg != nullptr && tokPg->skipMe())
		return nextPage->GetNext();
	return nextPage;
}

bool TokenSelectionWizardPage::skipMe()
{
	AudienceSelector2* wiz = dynamic_cast<AudienceSelector2*>(GetParent());

	if (wiz == nullptr || wiz->_vars == nullptr)
		return false;

	if (!wiz->_vars->_connector || wiz->_vars->_connector->tokenCount() != 1)
		return false;

	if (!wiz->_vars->_session)
	{
		wiz->_vars->_session = wiz->_vars->_connector->token(0)->openSession();
	}
	if (!wiz->_vars->_session || !wiz->_vars->_session->IsLoggedIn())
		return false;
	return true;
}

