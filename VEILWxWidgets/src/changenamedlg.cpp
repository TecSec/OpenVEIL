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
 * ChangeNameDlg type definition
 */

IMPLEMENT_DYNAMIC_CLASS( ChangeNameDlg, wxDialog )


/*
 * ChangeNameDlg event table definition
 */

BEGIN_EVENT_TABLE( ChangeNameDlg, wxDialog )

////@begin ChangeNameDlg event table entries
    EVT_TEXT( ID_CHANGENAME_NEWNAME, ChangeNameDlg::OnChangenameNewnameTextUpdated )
    EVT_BUTTON( wxID_HELP, ChangeNameDlg::OnHelpClick )
////@end ChangeNameDlg event table entries

END_EVENT_TABLE()


/*
 * ChangeNameDlg constructors
 */

ChangeNameDlg::ChangeNameDlg()
{
    Init();
}

ChangeNameDlg::ChangeNameDlg( wxWindow* parent, wxWindowID id, const wxString& caption, const wxPoint& pos, const wxSize& size, long style )
{
    Init();
    Create(parent, id, caption, pos, size, style);
}


/*
 * ChangeNameDlg creator
 */

bool ChangeNameDlg::Create( wxWindow* parent, wxWindowID id, const wxString& caption, const wxPoint& pos, const wxSize& size, long style )
{
////@begin ChangeNameDlg creation
    SetExtraStyle(wxWS_EX_VALIDATE_RECURSIVELY|wxWS_EX_BLOCK_EVENTS);
    wxDialog::Create( parent, id, caption, pos, size, style );

    CreateControls();
    if (GetSizer())
    {
        GetSizer()->SetSizeHints(this);
    }
    Centre();
////@end ChangeNameDlg creation
    return true;
}


/*
 * ChangeNameDlg destructor
 */

ChangeNameDlg::~ChangeNameDlg()
{
////@begin ChangeNameDlg destruction
////@end ChangeNameDlg destruction
}


/*
 * Member initialisation
 */

void ChangeNameDlg::Init()
{
////@begin ChangeNameDlg member initialisation
    lblDescription = NULL;
    lblCurrentName = NULL;
    edtNewName = NULL;
    btnOk = NULL;
////@end ChangeNameDlg member initialisation

	helpId = 0;
}


/*
 * Control creation for ChangeNameDlg
 */

void ChangeNameDlg::CreateControls()
{    
////@begin ChangeNameDlg content construction
    ChangeNameDlg* itemDialog1 = this;

    wxBoxSizer* itemBoxSizer2 = new wxBoxSizer(wxVERTICAL);
    itemDialog1->SetSizer(itemBoxSizer2);

    lblDescription = new wxStaticText( itemDialog1, wxID_CHANGE_NAME_TOP, _("Static text"), wxDefaultPosition, wxDefaultSize, 0 );
    itemBoxSizer2->Add(lblDescription, 0, wxGROW|wxALL, 5);

    wxFlexGridSizer* itemFlexGridSizer4 = new wxFlexGridSizer(0, 2, 0, 0);
    itemBoxSizer2->Add(itemFlexGridSizer4, 0, wxGROW|wxALL, 5);

    wxStaticText* itemStaticText5 = new wxStaticText( itemDialog1, wxID_STATIC, _("Current Name:"), wxDefaultPosition, wxDefaultSize, 0 );
    itemFlexGridSizer4->Add(itemStaticText5, 0, wxALIGN_RIGHT|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    lblCurrentName = new wxStaticText( itemDialog1, wxID_STATIC, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
    itemFlexGridSizer4->Add(lblCurrentName, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    wxStaticText* itemStaticText7 = new wxStaticText( itemDialog1, wxID_STATIC, _("New name:"), wxDefaultPosition, wxDefaultSize, 0 );
    itemFlexGridSizer4->Add(itemStaticText7, 0, wxALIGN_RIGHT|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    edtNewName = new wxTextCtrl( itemDialog1, ID_CHANGENAME_NEWNAME, wxEmptyString, wxDefaultPosition, wxSize(250, -1), 0 );
    if (ChangeNameDlg::ShowToolTips())
        edtNewName->SetToolTip(_("Enter the new name."));
    itemFlexGridSizer4->Add(edtNewName, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    itemFlexGridSizer4->AddGrowableCol(1);

    wxStdDialogButtonSizer* itemStdDialogButtonSizer9 = new wxStdDialogButtonSizer;

    itemBoxSizer2->Add(itemStdDialogButtonSizer9, 0, wxGROW|wxALL, 5);
    btnOk = new wxButton( itemDialog1, wxID_OK, _("&OK"), wxDefaultPosition, wxDefaultSize, 0 );
    btnOk->Enable(false);
    itemStdDialogButtonSizer9->AddButton(btnOk);

    wxButton* itemButton11 = new wxButton( itemDialog1, wxID_CANCEL, _("&Cancel"), wxDefaultPosition, wxDefaultSize, 0 );
    itemStdDialogButtonSizer9->AddButton(itemButton11);

    wxButton* itemButton12 = new wxButton( itemDialog1, wxID_HELP, _("&Help"), wxDefaultPosition, wxDefaultSize, 0 );
    itemStdDialogButtonSizer9->AddButton(itemButton12);

    itemStdDialogButtonSizer9->Realize();

////@end ChangeNameDlg content construction
}


/*
 * Should we show tooltips?
 */

bool ChangeNameDlg::ShowToolTips()
{
    return true;
}

/*
 * Get bitmap resources
 */

wxBitmap ChangeNameDlg::GetBitmapResource( const wxString& name )
{
    // Bitmap retrieval
////@begin ChangeNameDlg bitmap retrieval
    wxUnusedVar(name);
    return wxNullBitmap;
////@end ChangeNameDlg bitmap retrieval
}

/*
 * Get icon resources
 */

wxIcon ChangeNameDlg::GetIconResource( const wxString& name )
{
    // Icon retrieval
////@begin ChangeNameDlg icon retrieval
    wxUnusedVar(name);
    return wxNullIcon;
////@end ChangeNameDlg icon retrieval
}

void ChangeNameDlg::SetDescription(const tscrypto::tsCryptoString& setTo)
{
	if (lblDescription != nullptr)
		lblDescription->SetLabel(setTo.c_str());
}
void ChangeNameDlg::SetOldName(const tscrypto::tsCryptoString& setTo)
{
	if (lblCurrentName != nullptr)
		lblCurrentName->SetLabel(setTo.c_str());
}
void ChangeNameDlg::SetNewName(const tscrypto::tsCryptoString& setTo)
{
	if (edtNewName != nullptr)
		edtNewName->SetValue(setTo.c_str());
}
tscrypto::tsCryptoString ChangeNameDlg::GetNewName() const
{
	if (edtNewName == nullptr)
		return "";
	return edtNewName->GetValue().mbc_str().data();
}


/*
 * wxEVT_COMMAND_TEXT_UPDATED event handler for ID_CHANGENAME_NEWNAME
 */

void ChangeNameDlg::OnChangenameNewnameTextUpdated( wxCommandEvent& event )
{
	btnOk->Enable(edtNewName->GetValue().size() > 0);
}


/*
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_HELP
 */

void ChangeNameDlg::OnHelpClick( wxCommandEvent& event )
{
	std::shared_ptr<IVEILHttpHelpRegistry> help = ::TopServiceLocator()->get_instance<IVEILHttpHelpRegistry>("/WxWin/HelpRegistry");

	if (!help)
	{
		wxTsMessageBox(("Help is not available at this time."), ("Status"), wxOK);
	}
	else
	{
		help->DisplayHelpForWindowId(helpId, (XP_WINDOW)this);
	}
}

