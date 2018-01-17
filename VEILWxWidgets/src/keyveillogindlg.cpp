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
 * KeyVEILLoginDlg type definition
 */

IMPLEMENT_DYNAMIC_CLASS( KeyVEILLoginDlg, wxDialog )


/*
 * KeyVEILLoginDlg event table definition
 */

BEGIN_EVENT_TABLE( KeyVEILLoginDlg, wxDialog )

////@begin KeyVEILLoginDlg event table entries
    EVT_INIT_DIALOG( KeyVEILLoginDlg::OnInitDialog )
    EVT_BUTTON( wxID_HELP, KeyVEILLoginDlg::OnHelpClick )
    EVT_BUTTON( wxID_OK, KeyVEILLoginDlg::OnOkClick )
////@end KeyVEILLoginDlg event table entries

END_EVENT_TABLE()


/*
 * KeyVEILLoginDlg constructors
 */

KeyVEILLoginDlg::KeyVEILLoginDlg() : _vars(nullptr)
{
    Init();
}

KeyVEILLoginDlg::KeyVEILLoginDlg( wxWindow* parent, wxWindowID id, const wxString& caption, const wxPoint& pos, const wxSize& size, long style ) : _vars(nullptr)
{
    Init();
    Create(parent, id, caption, pos, size, style);
}


/*
 * KeyVEILLogin creator
 */

bool KeyVEILLoginDlg::Create( wxWindow* parent, wxWindowID id, const wxString& caption, const wxPoint& pos, const wxSize& size, long style )
{
////@begin KeyVEILLoginDlg creation
    SetExtraStyle(wxWS_EX_VALIDATE_RECURSIVELY|wxWS_EX_BLOCK_EVENTS);
    wxDialog::Create( parent, id, caption, pos, size, style );

    CreateControls();
    if (GetSizer())
    {
        GetSizer()->SetSizeHints(this);
    }
    Centre();
////@end KeyVEILLoginDlg creation
    return true;
}


/*
 * KeyVEILLoginDlg destructor
 */

KeyVEILLoginDlg::~KeyVEILLoginDlg()
{
////@begin KeyVEILLoginDlg destruction
////@end KeyVEILLoginDlg destruction
}


/*
 * Member initialisation
 */

void KeyVEILLoginDlg::Init()
{
////@begin KeyVEILLoginDlg member initialisation
    edtURL = NULL;
    edtUsername = NULL;
    edtPassword = NULL;
    edtStatus = NULL;
////@end KeyVEILLoginDlg member initialisation
}


/*
 * Control creation for KeyVEILLogin
 */

void KeyVEILLoginDlg::CreateControls()
{    
////@begin KeyVEILLoginDlg content construction
    KeyVEILLoginDlg* itemDialog1 = this;

    wxFlexGridSizer* itemFlexGridSizer2 = new wxFlexGridSizer(6, 1, 0, 0);
    itemDialog1->SetSizer(itemFlexGridSizer2);

    wxStaticBitmap* itemStaticBitmap3 = new wxStaticBitmap( itemDialog1, wxID_STATIC, itemDialog1->GetBitmapResource(wxT("tecseclogo.xpm")), wxDefaultPosition, wxSize(372, 73), 0 );
    itemFlexGridSizer2->Add(itemStaticBitmap3, 0, wxGROW|wxALL, 0);

    wxFlexGridSizer* itemFlexGridSizer4 = new wxFlexGridSizer(0, 2, 0, 0);
    itemFlexGridSizer2->Add(itemFlexGridSizer4, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    wxStaticText* itemStaticText5 = new wxStaticText( itemDialog1, wxID_STATIC, _("KeyVEIL URL:"), wxDefaultPosition, wxDefaultSize, 0 );
    itemFlexGridSizer4->Add(itemStaticText5, 0, wxALIGN_LEFT|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    edtURL = new wxTextCtrl( itemDialog1, ID_URL, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
    if (KeyVEILLoginDlg::ShowToolTips())
        edtURL->SetToolTip(_("Enter the URL for KeyVEIL here"));
    itemFlexGridSizer4->Add(edtURL, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxALL, 0);

    wxStaticText* itemStaticText7 = new wxStaticText( itemDialog1, wxID_STATIC, _("Username:"), wxDefaultPosition, wxDefaultSize, 0 );
    itemFlexGridSizer4->Add(itemStaticText7, 0, wxALIGN_LEFT|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    edtUsername = new wxTextCtrl( itemDialog1, ID_USERNAME, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
    if (KeyVEILLoginDlg::ShowToolTips())
        edtUsername->SetToolTip(_("This is the username that shall be used for accessing KeyVEIL"));
    itemFlexGridSizer4->Add(edtUsername, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxALL, 0);

    itemFlexGridSizer4->AddGrowableCol(1);

    wxStaticText* itemStaticText9 = new wxStaticText( itemDialog1, wxID_STATIC, _("Please enter the user password here:"), wxDefaultPosition, wxDefaultSize, 0 );
    itemFlexGridSizer2->Add(itemStaticText9, 0, wxALIGN_LEFT|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    edtPassword = new wxTextCtrl( itemDialog1, ID_PASSWORD, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_PASSWORD );
    edtPassword->SetMaxLength(64);
    if (KeyVEILLoginDlg::ShowToolTips())
        edtPassword->SetToolTip(_("Enter the password for the user to access KeyVEIL"));
    itemFlexGridSizer2->Add(edtPassword, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    edtStatus = new wxStaticText( itemDialog1, ID_STATUS, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
    edtStatus->Wrap(360);
    itemFlexGridSizer2->Add(edtStatus, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    wxStdDialogButtonSizer* itemStdDialogButtonSizer12 = new wxStdDialogButtonSizer;

    itemFlexGridSizer2->Add(itemStdDialogButtonSizer12, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxALL, 5);
    wxButton* itemButton13 = new wxButton( itemDialog1, wxID_CANCEL, _("&Cancel"), wxDefaultPosition, wxDefaultSize, 0 );
    itemStdDialogButtonSizer12->AddButton(itemButton13);

    wxButton* itemButton14 = new wxButton( itemDialog1, wxID_HELP, _("&Help"), wxDefaultPosition, wxDefaultSize, 0 );
    itemStdDialogButtonSizer12->AddButton(itemButton14);

    wxButton* itemButton15 = new wxButton( itemDialog1, wxID_OK, _("&OK"), wxDefaultPosition, wxDefaultSize, 0 );
    itemButton15->SetDefault();
    itemStdDialogButtonSizer12->AddButton(itemButton15);

    itemStdDialogButtonSizer12->Realize();

    itemFlexGridSizer2->AddGrowableRow(5);

////@end KeyVEILLoginDlg content construction
}


/*
 * Should we show tooltips?
 */

bool KeyVEILLoginDlg::ShowToolTips()
{
    return true;
}

/*
 * Get bitmap resources
 */

wxBitmap KeyVEILLoginDlg::GetBitmapResource( const wxString& name )
{
    return ::GetBitmapResource(name);
}

/*
 * Get icon resources
 */

wxIcon KeyVEILLoginDlg::GetIconResource( const wxString& name )
{
    // Icon retrieval
////@begin KeyVEILLoginDlg icon retrieval
    wxUnusedVar(name);
    return wxNullIcon;
////@end KeyVEILLoginDlg icon retrieval
}


/*
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_HELP
 */

void KeyVEILLoginDlg::OnHelpClick( wxCommandEvent& event )
{
	std::shared_ptr<IVEILHttpHelpRegistry> help = ::TopServiceLocator()->get_instance<IVEILHttpHelpRegistry>("/WxWin/HelpRegistry");

	if (!help)
	{
		wxTsMessageBox(("Help is not available at this time."), ("Status"), wxOK);
	}
	else
	{
		help->DisplayHelpForWindowId(winid_KeyVEILLogin, (XP_WINDOW)this);
	}
}


/*
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_OK
 */

void KeyVEILLoginDlg::OnOkClick( wxCommandEvent& event )
{
    if (_vars == nullptr)
        return;

    _vars->_url = edtURL->GetValue().c_str().AsChar();
    _vars->_username = edtUsername->GetValue().c_str().AsChar();
    _vars->_pinBuffer = edtPassword->GetValue().c_str().AsChar();

    event.StopPropagation();

    if ((int)tsStrLen(_vars->_pinBuffer.c_str()) < KEYVEIL_MIN_PIN_LEN)
    {
        char buff[MAX_PATH + 1];

        tsSnPrintf(buff, sizeof(buff), "The minimum password length is %d.", KEYVEIL_MIN_PIN_LEN);
        wxTsMessageBox(buff, "Error", wxOK);
    }
    else
    {
        _vars->_pinBuffer.resize(tsStrLen(_vars->_pinBuffer.c_str()));

        wxBusyCursor busyCursor;
        wxWindowDisabler disabler;
        wxBusyInfo busyInfo(_("Connecting to KeyVEIL..."));

        switch (_vars->_connector->connect(_vars->_url, _vars->_username, _vars->_pinBuffer))
        {
        case ConnectionStatus::connStatus_BadAuth:
            edtStatus->SetLabelText(_("The username or password was invalid."));
            break;
        case ConnectionStatus::connStatus_Connected:
            EndDialog(wxID_OK);
            break;
        case ConnectionStatus::connStatus_NoServer:
        {
            char buff[MAX_PATH + 1];

            tsStrCpy(buff, sizeof(buff), "The communications to the server was lost.");
            wxTsMessageBox(buff, "Error", wxOK);

            edtStatus->SetLabelText(buff);
        }
        break;
        case ConnectionStatus::connStatus_UrlBad:
        {
            char buff[MAX_PATH + 1];

            tsStrCpy(buff, sizeof(buff), "The specified URL is invalid.");
            wxTsMessageBox(buff, "Error", wxOK);
            edtStatus->SetLabelText(buff);
        }
        break;
        case ConnectionStatus::connStatus_WrongProtocol:
        {
            char buff[MAX_PATH + 1];

            tsStrCpy(buff, sizeof(buff), "The protocol specifier on the URL was not recognized.");
            wxTsMessageBox(buff, "Error", wxOK);
            edtStatus->SetLabelText(buff);
        }
        break;
        }
    }
}


/*
 * wxEVT_INIT_DIALOG event handler for ID_KEYVEILLOGIN
 */

void KeyVEILLoginDlg::OnInitDialog( wxInitDialogEvent& event )
{
    if (_vars == nullptr)
        return;

    std::shared_ptr<BasicVEILPreferences> prefs = BasicVEILPreferences::Create();

    prefs->loadValues();

    if (_vars->_url.size() == 0)
    {
        _vars->_url = prefs->getKeyVEILUrl();
    }
    if (_vars->_username.size() == 0)
    {
        _vars->_username = prefs->getKeyVEILUsername();
    }

    if (_vars->_connector->isConnected())
    {
        EndDialog(wxID_OK);
    }
    else
    {
        edtURL->SetValue(_vars->_url.c_str());
        edtUsername->SetValue(_vars->_username.c_str());
    }
    if (_vars->_url.size() > 0)
    {
        if (_vars->_username.size() > 0)
        {
            edtPassword->SetFocus();
        }
        else
        {
            edtUsername->SetFocus();
        }
    }
}

int KeyVEILLoginDlg::GetPinRetryCount(std::shared_ptr<IKeyVEILSession> session)
{
    return (int)session->retriesLeft();
}

void KeyVEILLoginDlg::setVariables(keyVeilLoginVariables* inVars)
{
    _vars = inVars;
}
