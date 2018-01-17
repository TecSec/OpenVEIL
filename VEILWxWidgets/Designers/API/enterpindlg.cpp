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

/*
 * EnterPin type definition
 */

IMPLEMENT_DYNAMIC_CLASS( EnterPin, wxDialog )


/*
 * EnterPin event table definition
 */

BEGIN_EVENT_TABLE( EnterPin, wxDialog )

////@begin EnterPin event table entries
    EVT_INIT_DIALOG( EnterPin::OnInitDialog )
    EVT_TEXT( ID_ENTERPIN_OLD_PASSWORD, EnterPin::OnEnterpinOldPasswordTextUpdated )
    EVT_TEXT( ID_ENTERPIN_NEW_PASSWORD, EnterPin::OnEnterpinNewPasswordTextUpdated )
    EVT_TEXT( ID_ENTERPIN_VERIFY_PASSWORD, EnterPin::OnEnterpinVerifyPasswordTextUpdated )
    EVT_BUTTON( wxID_OK, EnterPin::OnOkClick )
    EVT_BUTTON( wxID_CANCEL, EnterPin::OnCancelClick )
    EVT_BUTTON( wxID_APPLY, EnterPin::OnApplyClick )
    EVT_BUTTON( wxID_HELP, EnterPin::OnHelpClick )
////@end EnterPin event table entries

END_EVENT_TABLE()


/*
 * EnterPin constructors
 */

EnterPin::EnterPin() : _vars(nullptr)
{
    Init();
}

EnterPin::EnterPin( wxWindow* parent, wxWindowID id, const wxString& caption, const wxPoint& pos, const wxSize& size, long style ) : _vars(nullptr)
{
    Init();
    Create(parent, id, caption, pos, size, style);
}


/*
 * EnterPin creator
 */

bool EnterPin::Create( wxWindow* parent, wxWindowID id, const wxString& caption, const wxPoint& pos, const wxSize& size, long style )
{
////@begin EnterPin creation
    SetExtraStyle(wxWS_EX_VALIDATE_RECURSIVELY|wxWS_EX_BLOCK_EVENTS);
    wxDialog::Create( parent, id, caption, pos, size, style );

    CreateControls();
    if (GetSizer())
    {
        GetSizer()->SetSizeHints(this);
    }
    Centre();
////@end EnterPin creation
    return true;
}


/*
 * EnterPin destructor
 */

EnterPin::~EnterPin()
{
////@begin EnterPin destruction
////@end EnterPin destruction
}


/*
 * Member initialisation
 */

void EnterPin::Init()
{
////@begin EnterPin member initialisation
    lblExplain = NULL;
    lblOldPassword = NULL;
    edtOldPassword = NULL;
    lblNewPassword = NULL;
    edtNewPassword = NULL;
    lblVerifyPassword = NULL;
    edtVerifyPassword = NULL;
    lblPasswordStrength = NULL;
    edtPasswordStrength = NULL;
    lblStatus = NULL;
    btnOK = NULL;
    btnCancel = NULL;
    btnAbout = NULL;
    btnHelp = NULL;
////@end EnterPin member initialisation
}


/*
 * Control creation for EnterPin
 */

void EnterPin::CreateControls()
{    
////@begin EnterPin content construction
    EnterPin* itemDialog1 = this;

    wxBoxSizer* itemBoxSizer2 = new wxBoxSizer(wxVERTICAL);
    itemDialog1->SetSizer(itemBoxSizer2);

    lblExplain = new wxStaticText( itemDialog1, ID_ENTERPIN_PASSWORD_EXPLAIN, _("Static text"), wxDefaultPosition, wxDefaultSize, 0 );
    lblExplain->Wrap(300);
    itemBoxSizer2->Add(lblExplain, 0, wxGROW|wxALL, 5);

    wxFlexGridSizer* itemFlexGridSizer4 = new wxFlexGridSizer(0, 2, 0, 0);
    itemBoxSizer2->Add(itemFlexGridSizer4, 0, wxALIGN_CENTER_HORIZONTAL|wxALL, 5);

    lblOldPassword = new wxStaticText( itemDialog1, wxID_STATIC, _("Current Password:"), wxDefaultPosition, wxDefaultSize, 0 );
    itemFlexGridSizer4->Add(lblOldPassword, 0, wxALIGN_RIGHT|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    edtOldPassword = new wxTextCtrl( itemDialog1, ID_ENTERPIN_OLD_PASSWORD, wxEmptyString, wxDefaultPosition, wxSize(250, -1), wxTE_PASSWORD );
    if (EnterPin::ShowToolTips())
        edtOldPassword->SetToolTip(_("Enter the current password."));
    itemFlexGridSizer4->Add(edtOldPassword, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    lblNewPassword = new wxStaticText( itemDialog1, wxID_STATIC, _("New Password:"), wxDefaultPosition, wxDefaultSize, 0 );
    itemFlexGridSizer4->Add(lblNewPassword, 0, wxALIGN_RIGHT|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    edtNewPassword = new wxTextCtrl( itemDialog1, ID_ENTERPIN_NEW_PASSWORD, wxEmptyString, wxDefaultPosition, wxSize(250, -1), wxTE_PASSWORD );
    if (EnterPin::ShowToolTips())
        edtNewPassword->SetToolTip(_("Enter the new password"));
    itemFlexGridSizer4->Add(edtNewPassword, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    lblVerifyPassword = new wxStaticText( itemDialog1, wxID_STATIC, _("Verify Password:"), wxDefaultPosition, wxDefaultSize, 0 );
    itemFlexGridSizer4->Add(lblVerifyPassword, 0, wxALIGN_RIGHT|wxALIGN_CENTER_VERTICAL|wxLEFT|wxRIGHT|wxBOTTOM, 5);

    edtVerifyPassword = new wxTextCtrl( itemDialog1, ID_ENTERPIN_VERIFY_PASSWORD, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_PASSWORD );
    if (EnterPin::ShowToolTips())
        edtVerifyPassword->SetToolTip(_("Retype the new password"));
    itemFlexGridSizer4->Add(edtVerifyPassword, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxLEFT|wxRIGHT|wxBOTTOM, 5);

    lblPasswordStrength = new wxStaticText( itemDialog1, wxID_STATIC, _("Password Strength:"), wxDefaultPosition, wxDefaultSize, 0 );
    itemFlexGridSizer4->Add(lblPasswordStrength, 0, wxALIGN_RIGHT|wxALIGN_CENTER_VERTICAL|wxLEFT|wxRIGHT|wxBOTTOM, 5);

    edtPasswordStrength = new PasswordGauge( itemDialog1, ID_ENTERPIN_PASSWORD_STRENGTH, wxDefaultPosition, wxSize(-1, 20), wxSIMPLE_BORDER );
    if (EnterPin::ShowToolTips())
        edtPasswordStrength->SetToolTip(_("Shows the relative strength of the new password."));
    edtPasswordStrength->Enable(false);
    itemFlexGridSizer4->Add(edtPasswordStrength, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxLEFT|wxRIGHT|wxBOTTOM, 5);

    itemFlexGridSizer4->AddGrowableCol(1);

    lblStatus = new wxStaticText( itemDialog1, ID_ENTERPIN_STATUS, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
    lblStatus->Wrap(360);
    itemBoxSizer2->Add(lblStatus, 0, wxGROW|wxALL, 5);

    wxStdDialogButtonSizer* itemStdDialogButtonSizer14 = new wxStdDialogButtonSizer;

    itemBoxSizer2->Add(itemStdDialogButtonSizer14, 0, wxGROW|wxALL, 5);
    btnOK = new wxButton( itemDialog1, wxID_OK, _("&OK"), wxDefaultPosition, wxDefaultSize, 0 );
    btnOK->SetDefault();
    itemStdDialogButtonSizer14->AddButton(btnOK);

    btnCancel = new wxButton( itemDialog1, wxID_CANCEL, _("&Cancel"), wxDefaultPosition, wxDefaultSize, 0 );
    itemStdDialogButtonSizer14->AddButton(btnCancel);

    btnAbout = new wxButton( itemDialog1, wxID_APPLY, _("&About"), wxDefaultPosition, wxDefaultSize, 0 );
    itemStdDialogButtonSizer14->AddButton(btnAbout);

    btnHelp = new wxButton( itemDialog1, wxID_HELP, _("&Help"), wxDefaultPosition, wxDefaultSize, 0 );
    itemStdDialogButtonSizer14->AddButton(btnHelp);

    itemStdDialogButtonSizer14->Realize();

////@end EnterPin content construction
	configureControls();
	if (_vars != nullptr && _vars->helpId > 0)
	{
        btnAbout->Enable(false);
		btnAbout->Show(false);
		btnHelp->Show(true);
	}
	else
	{
		btnAbout->Show(true);
		btnHelp->Show(false);
        btnHelp->Enable(false);
	}
}


void EnterPin::configureControls()
{
	if (_vars != nullptr && edtPasswordStrength != nullptr)
	{
		if (_vars->m_changingPin)
		{
			edtPasswordStrength->SetWeak(_vars->weakStrength);
			edtPasswordStrength->SetStrong(_vars->strongStrength);
			edtPasswordStrength->SetMax(_vars->maxStrength);

			lblOldPassword->Show(true);
			edtOldPassword->Show(true);
            edtOldPassword->Enable(true);
			lblNewPassword->Show(true);
			edtNewPassword->Show(true);
            edtNewPassword->Enable(true);
			lblVerifyPassword->Show(true);
			edtVerifyPassword->Show(true);
            edtVerifyPassword->Enable(true);
			lblPasswordStrength->Show(true);
			edtPasswordStrength->Show(true);
            edtPasswordStrength->Enable(false);
		}
		else if (_vars->m_creatingPin)
		{
			edtPasswordStrength->SetWeak(_vars->weakStrength);
			edtPasswordStrength->SetStrong(_vars->strongStrength);
			edtPasswordStrength->SetMax(_vars->maxStrength);

			lblOldPassword->Show(false);
            edtOldPassword->Enable(false);
			edtOldPassword->Show(false);
			lblVerifyPassword->Show(true);
            edtVerifyPassword->Enable(true);
			edtVerifyPassword->Show(true);
			lblNewPassword->Show(true);
			edtNewPassword->Show(true);
            edtNewPassword->Enable(true);
            edtNewPassword->SetFocus();
			lblPasswordStrength->Show(true);
			edtPasswordStrength->Show(true);
            edtPasswordStrength->Enable(false);
		}
		else
		{
			lblNewPassword->Show(true);
			edtNewPassword->Show(true);
            edtNewPassword->Enable(true);
			lblNewPassword->SetLabel("Password:");

			lblOldPassword->Show(false);
            edtOldPassword->Enable(false);
			edtOldPassword->Show(false);
			lblVerifyPassword->Show(false);
            edtVerifyPassword->Enable(false);
			edtVerifyPassword->Show(false);
			lblPasswordStrength->Show(false);
            edtPasswordStrength->Enable(false);
			edtPasswordStrength->Show(false);
		}
		edtOldPassword->SetMaxLength(_vars->maxLen);
		edtNewPassword->SetMaxLength(_vars->maxLen);
		edtVerifyPassword->SetMaxLength(_vars->maxLen);

	Fit();
	btnOK->Enable(false);
	}
}
void EnterPin::setExplanation(const tscrypto::tsCryptoString& setTo)
{
	lblExplain->SetLabel(setTo.c_str());
	Fit();
}
void EnterPin::setStatus(const tscrypto::tsCryptoString& setTo)
{
	lblStatus->SetLabel(setTo.c_str());
	Fit();
}
void EnterPin::setVariables(enterPinVariables* vars)
{
	_vars = vars;
	configureControls();
}


/*
 * wxEVT_INIT_DIALOG event handler for ID_ENTERPIN
 */

void EnterPin::OnInitDialog( wxInitDialogEvent& event )
{
    event.Skip();
}


/*
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_OK
 */

void EnterPin::OnOkClick( wxCommandEvent& event )
{
    event.StopPropagation();
	if (_vars == nullptr)
	{
    event.Skip();
		return;
	}
	if (_vars->m_changingPin)
	{
		if (edtNewPassword->GetValue() != edtVerifyPassword->GetValue())
		{
			wxMessageBox("The passwords do not match.");
			return;
		}
		_vars->m_oldPin = edtOldPassword->GetValue().mbc_str().data();
	}
	else if (_vars->m_creatingPin)
	{
		if (edtNewPassword->GetValue() != edtVerifyPassword->GetValue())
		{
			wxMessageBox("The passwords do not match.");
			return;
		}
	}
	_vars->m_pin = edtNewPassword->GetValue().mbc_str().data();
	if (_vars->m_pin.size() < _vars->minLen)
	{
		wxMessageBox(wxString("The minimum password length is ") << _vars->minLen << " characters.");
		return;
	}
	if (_vars->m_pin.size() > _vars->maxLen)
	{
		wxMessageBox(wxString("The maximum password length is ") << _vars->maxLen << " characters.");
		return;
	}
	if (!!_vars->pinTesterFn && !_vars->pinTesterFn(_vars->DlgWrapper, _vars->m_pin))
	{
		return;
	}
	//EndDialog(wxID_OK);
	event.Skip();
}


/*
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_CANCEL
 */

void EnterPin::OnCancelClick( wxCommandEvent& event )
{
    event.Skip();
}


/*
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_APPLY
 */

void EnterPin::OnApplyClick( wxCommandEvent& event )
{
	std::shared_ptr<IVEILWxUIBase> dlg = ::TopServiceLocator()->get_instance<IVEILWxUIBase>("/WxWin/AboutCkm");

	dlg->DisplayModal((XP_WINDOW)this);
}


/*
 * Should we show tooltips?
 */

bool EnterPin::ShowToolTips()
{
    return true;
}

/*
 * Get bitmap resources
 */

wxBitmap EnterPin::GetBitmapResource( const wxString& name )
{
	return ::GetBitmapResource(name);
}

/*
 * Get icon resources
 */

wxIcon EnterPin::GetIconResource( const wxString& name )
{
	return ::GetIconResource(name);
}

/*
 * wxEVT_COMMAND_TEXT_UPDATED event handler for ID_ENTERPASSWORD
 */

void EnterPin::OnEnterpinOldPasswordTextUpdated( wxCommandEvent& event )
{
    event.Skip();
	if (_vars != nullptr)
	{
		if (_vars->m_changingPin)
		{
			if (edtOldPassword->GetValue().size() == 0)
			{
				btnOK->Enable(false);
				return;
			}
		}
		OnEnterpinNewPasswordTextUpdated(event);
	}
	else
	{
		btnOK->Enable(false);
	}
}


/*
 * wxEVT_COMMAND_TEXT_UPDATED event handler for ID_ENTERPIN_VERIFY
 */

void EnterPin::OnEnterpinVerifyPasswordTextUpdated( wxCommandEvent& event )
{
    event.Skip();
	if (_vars != nullptr)
	{
		if (_vars->m_changingPin || _vars->m_creatingPin)
		{
			if (_vars->m_changingPin)
			{
				if (edtOldPassword->GetValue().size() == 0)
				{
					btnOK->Enable(false);
					return;
				}
			}
			if (edtNewPassword->GetValue() != edtVerifyPassword->GetValue())
			{
				btnOK->Enable(false);
				return;
			}
		}
		if (edtNewPassword->GetValue().size() < _vars->minLen || edtNewPassword->GetValue().size() > _vars->maxLen)
		{
			btnOK->Enable(false);
			return;
		}
		btnOK->Enable(true);
	}
	else
	{
		btnOK->Enable(false);
	}
}


/*
 * wxEVT_COMMAND_TEXT_UPDATED event handler for ID_NEW_PASSWORD
 */

void EnterPin::OnEnterpinNewPasswordTextUpdated( wxCommandEvent& event )
{
    event.Skip();
	if (_vars != nullptr)
	{
		_vars->m_pin = edtNewPassword->GetValue().mbc_str().data();
		if (_vars->m_changingPin || _vars->m_creatingPin)
		{
			if (!!_vars->pinStrengthFn)
			{
				edtPasswordStrength->SetValue(_vars->pinStrengthFn(_vars->DlgWrapper, _vars->m_pin));
			}
			if (_vars->m_changingPin)
			{
				if (edtOldPassword->GetValue().size() == 0)
				{
					btnOK->Enable(false);
					return;
				}
			}
			if (edtNewPassword->GetValue() != edtVerifyPassword->GetValue())
			{
				btnOK->Enable(false);
				return;
			}
		}
		if (edtNewPassword->GetValue().size() < _vars->minLen || edtNewPassword->GetValue().size() > _vars->maxLen)
		{
			btnOK->Enable(false);
			return;
		}
		btnOK->Enable(true);
	}
	else
	{
		btnOK->Enable(false);
	}
}


/*
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_HELP
 */

void EnterPin::OnHelpClick( wxCommandEvent& event )
{
	std::shared_ptr<IVEILHttpHelpRegistry> help = ::TopServiceLocator()->get_instance<IVEILHttpHelpRegistry>("/WxWin/HelpRegistry");

	if (_vars == nullptr || !help)
	{
		wxTsMessageBox(("Help is not available at this time."), ("Status"), wxOK);
	}
	else
	{
		help->DisplayHelpForWindowId(_vars->helpId, (XP_WINDOW)this);
	}
}

