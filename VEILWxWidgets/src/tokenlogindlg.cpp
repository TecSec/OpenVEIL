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

// For compilers that support precompilation, includes "wx/wx.h".
#include "stdafx.h"

////@begin includes
////@end includes


////@begin XPM images
////@end XPM images


/*
 * TokenLogin type definition
 */

IMPLEMENT_DYNAMIC_CLASS( TokenLogin, wxDialog )


/*
 * TokenLogin event table definition
 */

BEGIN_EVENT_TABLE( TokenLogin, wxDialog )

////@begin TokenLogin event table entries
    EVT_INIT_DIALOG( TokenLogin::OnInitDialog )
    EVT_BUTTON( wxID_OK, TokenLogin::OnOkClick )
    EVT_BUTTON( wxID_CANCEL, TokenLogin::OnCancelClick )
    EVT_BUTTON( wxID_HELP, TokenLogin::OnHelpClick )
////@end TokenLogin event table entries

END_EVENT_TABLE()


/*
 * TokenLogin constructors
 */

TokenLogin::TokenLogin() : _vars(nullptr)
{
    Init();
}

TokenLogin::TokenLogin( wxWindow* parent, wxWindowID id, const wxString& caption, const wxPoint& pos, const wxSize& size, long style ) : _vars(nullptr)
{
    Init();
    Create(parent, id, caption, pos, size, style);
}


/*
 * TokenLogin creator
 */

bool TokenLogin::Create( wxWindow* parent, wxWindowID id, const wxString& caption, const wxPoint& pos, const wxSize& size, long style )
{
////@begin TokenLogin creation
    SetExtraStyle(wxWS_EX_VALIDATE_RECURSIVELY|wxWS_EX_BLOCK_EVENTS);
    wxDialog::Create( parent, id, caption, pos, size, style );

    CreateControls();
    if (GetSizer())
    {
        GetSizer()->SetSizeHints(this);
    }
    Centre();
////@end TokenLogin creation
    return true;
}


/*
 * TokenLogin destructor
 */

TokenLogin::~TokenLogin()
{
////@begin TokenLogin destruction
////@end TokenLogin destruction
}


/*
 * Member initialisation
 */

void TokenLogin::Init()
{
////@begin TokenLogin member initialisation
    lblTokenName = NULL;
    edtPassword = NULL;
    lblStatus = NULL;
    btnOK = NULL;
    btnCancel = NULL;
////@end TokenLogin member initialisation
}


/*
 * Control creation for TokenLogin
 */

void TokenLogin::CreateControls()
{    
////@begin TokenLogin content construction
    TokenLogin* itemDialog1 = this;

    wxFlexGridSizer* itemFlexGridSizer2 = new wxFlexGridSizer(0, 1, 0, 0);
    itemDialog1->SetSizer(itemFlexGridSizer2);

    wxStaticBitmap* itemStaticBitmap3 = new wxStaticBitmap( itemDialog1, wxID_STATIC, itemDialog1->GetBitmapResource(wxT("tecseclogo.xpm")), wxDefaultPosition, wxSize(372, 73), 0 );
    itemFlexGridSizer2->Add(itemStaticBitmap3, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 0);

    wxFlexGridSizer* itemFlexGridSizer4 = new wxFlexGridSizer(0, 2, 0, 0);
    itemFlexGridSizer2->Add(itemFlexGridSizer4, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    wxStaticText* itemStaticText5 = new wxStaticText( itemDialog1, wxID_STATIC, _("Token Name:"), wxDefaultPosition, wxDefaultSize, 0 );
    itemFlexGridSizer4->Add(itemStaticText5, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    lblTokenName = new wxStaticText( itemDialog1, ID_TOKENNAME, _("Static text"), wxDefaultPosition, wxDefaultSize, 0 );
    lblTokenName->Wrap(300);
    itemFlexGridSizer4->Add(lblTokenName, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    itemFlexGridSizer2->Add(5, 5, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    wxStaticText* itemStaticText8 = new wxStaticText( itemDialog1, wxID_STATIC, _("Please enter the token password here:"), wxDefaultPosition, wxDefaultSize, 0 );
    itemFlexGridSizer2->Add(itemStaticText8, 0, wxALIGN_LEFT|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    edtPassword = new wxTextCtrl( itemDialog1, ID_TEXTCTRL, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_PASSWORD );
    if (TokenLogin::ShowToolTips())
        edtPassword->SetToolTip(_("Enter the password for this token."));
    itemFlexGridSizer2->Add(edtPassword, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    lblStatus = new wxStaticText( itemDialog1, ID_TOKEN_STATUS, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
    lblStatus->Wrap(360);
    itemFlexGridSizer2->Add(lblStatus, 0, wxALIGN_LEFT|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    wxStdDialogButtonSizer* itemStdDialogButtonSizer11 = new wxStdDialogButtonSizer;

    itemFlexGridSizer2->Add(itemStdDialogButtonSizer11, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxALL, 5);
    btnOK = new wxButton( itemDialog1, wxID_OK, _("&OK"), wxDefaultPosition, wxDefaultSize, 0 );
    btnOK->SetDefault();
    itemStdDialogButtonSizer11->AddButton(btnOK);

    btnCancel = new wxButton( itemDialog1, wxID_CANCEL, _("&Cancel"), wxDefaultPosition, wxDefaultSize, 0 );
    itemStdDialogButtonSizer11->AddButton(btnCancel);

    wxButton* itemButton14 = new wxButton( itemDialog1, wxID_HELP, _("&Help"), wxDefaultPosition, wxDefaultSize, 0 );
    itemStdDialogButtonSizer11->AddButton(itemButton14);

    itemStdDialogButtonSizer11->Realize();

////@end TokenLogin content construction
}


/*
 * Should we show tooltips?
 */

bool TokenLogin::ShowToolTips()
{
    return true;
}

/*
 * Get bitmap resources
 */

wxBitmap TokenLogin::GetBitmapResource( const wxString& name )
{
    return ::GetBitmapResource(name);
}

/*
 * Get icon resources
 */

wxIcon TokenLogin::GetIconResource( const wxString& name )
{
    // Icon retrieval
////@begin TokenLogin icon retrieval
    wxUnusedVar(name);
    return wxNullIcon;
////@end TokenLogin icon retrieval
}


/*
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_OK
 */

void TokenLogin::OnOkClick( wxCommandEvent& event )
{
    event.StopPropagation();

    if (_vars == nullptr)
        return;

    _vars->_pinBuffer = edtPassword->GetValue().c_str().AsChar();
    if ((int)tsStrLen(_vars->_pinBuffer.c_str()) < _vars->_minLen)
    {
        char buff[MAX_PATH + 1];

        tsSnPrintf(buff, sizeof(buff), "The minimum password length is %d.", _vars->_minLen);
        wxTsMessageBox(buff, "Error", wxOK);
    }
    else
    {
        _vars->_pinBuffer.resize(tsStrLen(_vars->_pinBuffer.c_str()));
        LoginStatus result = _vars->_session->Login(_vars->_pinBuffer);
        switch (result)
        {
        case LoginStatus::loginStatus_BadAuth:
            if (_vars->_session->retriesLeft() == 0)
            {
                wxTsMessageBox("The token is locked.", "Error", wxOK);
                EndDialog(wxID_OK);
            }
            else if (_vars->_session->retriesLeft() == 1)
            {
                lblStatus->SetLabel("This token has one try left.");
            }
            else
            {
                lblStatus->SetLabel("The login count is low.");
            }
            break;
        case LoginStatus::loginStatus_Connected:
            //
            // Establish the pin in any SSO system that is currently active
            //
            //if (sso != NULL)
            //{
            //	if (wxTsMessageBox(hWnd, "Would you like to have the system remember this token password?", "Single Sign On", MB_YESNO | MB_ICONQUESTION) == wxID_YES)
            //		sso->SSOSetPin(_pinBuffer);
            //	else
            //		sso->SSOSetPin("");
            //}
            EndDialog(wxID_OK);
            break;
        case LoginStatus::loginStatus_NoServer:
        {
            char buff[MAX_PATH + 1];

            tsStrCpy(buff, sizeof(buff), "The communications to the server was lost.");
            wxTsMessageBox(buff, "Error", wxOK);
            lblStatus->SetLabel(buff);
        }
        break;
        }
    }
}


/*
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_CANCEL
 */

void TokenLogin::OnCancelClick( wxCommandEvent& event )
{
    event.StopPropagation();
    EndDialog(wxID_CANCEL);
}


/*
 * wxEVT_INIT_DIALOG event handler for ID_TOKENLOGIN
 */

void TokenLogin::OnInitDialog( wxInitDialogEvent& event )
{
    tscrypto::tsCryptoString buff;

    if (_vars == nullptr)
        return;

    edtPassword->SetMaxLength(_vars->_maxLen);

    if (!_vars->_session)
    {
        wxTsMessageBox("You must call Start before displaying this dialog.", "ERROR", wxOK);
    }

    if (_vars->_session->GetProfile()->exists_tokenName())
        buff = *_vars->_session->GetProfile()->get_tokenName();
    if (buff.size() > 0)
    {
        lblTokenName->SetLabel(buff.c_str());
    }
    else
        lblTokenName->SetLabel("unknown token");

    //_result = E_FAIL;
    if (_vars->_session->IsLoggedIn())
    {
        //_result = S_OK;
        EndDialog(wxID_OK);
    }
    else
    {
        switch (GetPinRetryCount(_vars->_session))
        {
        case 0:
            if (_vars->_session->LastKeyVEILStatus() == 401 || _vars->_session->LastKeyVEILStatus() == 440)
            {
                wxTsMessageBox("The KeyVEIL connector is no longer authenticated.", "Error", wxOK);
                //_result = ERROR_NOT_AUTHENTICATED;
            }
            else
            {
                wxTsMessageBox("The token is locked.", "Error", wxOK);
                //_result = ERROR_ACCOUNT_LOCKED_OUT;
            }
            EndDialog(wxID_OK);
            break;
        case 1:
            lblStatus->SetLabel("This token has one try left.");
            break;
        case 2:
            lblStatus->SetLabel("At least one login attempt has failed.");
            break;
        }
        //
        // Now we need to check for the authenticated path
        //
        //if (_session->UsesAuthenticatedPath())
        //{
        //	_result = _session->Login("TecSec");
        //	if (_result == 0)
        //		EndDialog(hWnd, wxID_OK);
        //	else
        //	{
        //		wxTsMessageBox(hWnd, "The password for this token does not match the stored password.  Please enter the token password.", "Error", MB_OK);
        //	}
        //}
        //else
        //{
        //	HRESULT hr;
        //	//
        //	// Now we need to check for SSO systems.
        //	//
        //	if (sso != NULL)
        //	{
        //		if ((hr = sso->SSOLogin()) == S_OK || SUCCEEDED(hr))
        //		{
        //			if (hr == XP_HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED))
        //			{
        //				wxTsMessageBox(hWnd, "The Single Sign-on provider supplied an incorrect password for this Token.", "Error", MB_OK | MB_ICONWARNING);
        //			}
        //			result = hr;
        //			EndDialog(hWnd, wxID_OK);
        //		}
        //	}
        //}
    }
}

int TokenLogin::GetPinRetryCount(std::shared_ptr<IKeyVEILSession> session)
{
    return (int)session->retriesLeft();
}

void TokenLogin::setVariables(tokenLoginVariables* inVars)
{
    _vars = inVars;
}


/*
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_HELP
 */

void TokenLogin::OnHelpClick( wxCommandEvent& event )
{
	std::shared_ptr<IVEILHttpHelpRegistry> help = ::TopServiceLocator()->get_instance<IVEILHttpHelpRegistry>("/WxWin/HelpRegistry");

	if (!help)
	{
		wxTsMessageBox(("Help is not available at this time."), ("Status"), wxOK);
	}
	else
	{
		help->DisplayHelpForWindowId(winid_StandardTokenLogin, (XP_WINDOW)this);
	}
}

