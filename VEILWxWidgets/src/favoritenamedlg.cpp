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
 * FavoriteNameDlg type definition
 */

IMPLEMENT_DYNAMIC_CLASS( FavoriteNameDlg, wxDialog )


/*
 * FavoriteNameDlg event table definition
 */

BEGIN_EVENT_TABLE( FavoriteNameDlg, wxDialog )

////@begin FavoriteNameDlg event table entries
    EVT_INIT_DIALOG( FavoriteNameDlg::OnInitDialog )
    EVT_TEXT( ID_NAME, FavoriteNameDlg::OnNameTextUpdated )
    EVT_BUTTON( wxID_OK, FavoriteNameDlg::OnOkClick )
    EVT_BUTTON( wxID_CANCEL, FavoriteNameDlg::OnCancelClick )
    EVT_BUTTON( wxID_HELP, FavoriteNameDlg::OnHelpClick )
////@end FavoriteNameDlg event table entries

END_EVENT_TABLE()


/*
 * FavoriteNameDlg constructors
 */

FavoriteNameDlg::FavoriteNameDlg()
{
    Init();
}

FavoriteNameDlg::FavoriteNameDlg( wxWindow* parent, wxWindowID id, const wxString& caption, const wxPoint& pos, const wxSize& size, long style )
{
    Init();
    Create(parent, id, caption, pos, size, style);
}


/*
 * FavoriteName creator
 */

bool FavoriteNameDlg::Create( wxWindow* parent, wxWindowID id, const wxString& caption, const wxPoint& pos, const wxSize& size, long style )
{
////@begin FavoriteNameDlg creation
    SetExtraStyle(wxWS_EX_VALIDATE_RECURSIVELY|wxWS_EX_BLOCK_EVENTS);
    wxDialog::Create( parent, id, caption, pos, size, style );

    CreateControls();
    if (GetSizer())
    {
        GetSizer()->SetSizeHints(this);
    }
    Centre();
////@end FavoriteNameDlg creation
    return true;
}


/*
 * FavoriteNameDlg destructor
 */

FavoriteNameDlg::~FavoriteNameDlg()
{
////@begin FavoriteNameDlg destruction
////@end FavoriteNameDlg destruction
}


/*
 * Member initialisation
 */

void FavoriteNameDlg::Init()
{
////@begin FavoriteNameDlg member initialisation
    edtName = NULL;
    btnOK = NULL;
    btnCancel = NULL;
////@end FavoriteNameDlg member initialisation
}


/*
 * Control creation for FavoriteName
 */

void FavoriteNameDlg::CreateControls()
{    
////@begin FavoriteNameDlg content construction
    FavoriteNameDlg* itemDialog1 = this;

    wxFlexGridSizer* itemFlexGridSizer2 = new wxFlexGridSizer(0, 1, 0, 0);
    itemDialog1->SetSizer(itemFlexGridSizer2);

    wxStaticText* itemStaticText3 = new wxStaticText( itemDialog1, wxID_STATIC, _("Enter the name by which this favorite shall be known:"), wxDefaultPosition, wxSize(350, -1), 0 );
    itemFlexGridSizer2->Add(itemStaticText3, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    edtName = new wxTextCtrl( itemDialog1, ID_NAME, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
    edtName->SetMaxLength(50);
    itemFlexGridSizer2->Add(edtName, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    wxStdDialogButtonSizer* itemStdDialogButtonSizer5 = new wxStdDialogButtonSizer;

    itemFlexGridSizer2->Add(itemStdDialogButtonSizer5, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxALL, 5);
    btnOK = new wxButton( itemDialog1, wxID_OK, _("&OK"), wxDefaultPosition, wxDefaultSize, 0 );
    itemStdDialogButtonSizer5->AddButton(btnOK);

    btnCancel = new wxButton( itemDialog1, wxID_CANCEL, _("&Cancel"), wxDefaultPosition, wxDefaultSize, 0 );
    itemStdDialogButtonSizer5->AddButton(btnCancel);

    wxButton* itemButton8 = new wxButton( itemDialog1, wxID_HELP, _("&Help"), wxDefaultPosition, wxDefaultSize, 0 );
    itemStdDialogButtonSizer5->AddButton(itemButton8);

    itemStdDialogButtonSizer5->Realize();

////@end FavoriteNameDlg content construction
}


/*
 * Should we show tooltips?
 */

bool FavoriteNameDlg::ShowToolTips()
{
    return true;
}

/*
 * Get bitmap resources
 */

wxBitmap FavoriteNameDlg::GetBitmapResource( const wxString& name )
{
    return ::GetBitmapResource(name);
}

/*
 * Get icon resources
 */

wxIcon FavoriteNameDlg::GetIconResource( const wxString& name )
{
    return ::GetIconResource(name);
}


/*
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_OK
 */

void FavoriteNameDlg::OnOkClick( wxCommandEvent& event )
{
    event.StopPropagation();

    _name = edtName->GetValue().c_str().AsChar();
    _name.Trim();
    if (_name.size() == 0)
    {
        wxMessageBox(tscrypto::tsCryptoString().Format("The favorite name is empty.").c_str(), "Error", wxICON_STOP | wxOK);
        return;
    }

    EndDialog(wxID_OK);
}


/*
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_CANCEL
 */

void FavoriteNameDlg::OnCancelClick( wxCommandEvent& event )
{
	EndDialog(wxID_CANCEL);
}


/*
 * wxEVT_COMMAND_TEXT_UPDATED event handler for ID_NAME
 */

void FavoriteNameDlg::OnNameTextUpdated( wxCommandEvent& event )
{
	btnOK->Enable(edtName->GetValue().size() > 0);
}


/*
 * wxEVT_INIT_DIALOG event handler for ID_FAVORITENAME
 */

void FavoriteNameDlg::OnInitDialog( wxInitDialogEvent& event )
{
    edtName->SetValue(_name.c_str());
    btnOK->Enable(edtName->GetValue().size() > 0);
}

tscrypto::tsCryptoString FavoriteNameDlg::get_name() const
{
	return _name;
}
void FavoriteNameDlg::set_name(tscrypto::tsCryptoString setTo)
{
	_name = setTo;
}


/*
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_HELP
 */

void FavoriteNameDlg::OnHelpClick( wxCommandEvent& event )
{
	std::shared_ptr<IVEILHttpHelpRegistry> help = ::TopServiceLocator()->get_instance<IVEILHttpHelpRegistry>("/WxWin/HelpRegistry");

	if (!help)
	{
		wxTsMessageBox(("Help is not available at this time."), ("Status"), wxOK);
	}
	else
	{
		help->DisplayHelpForWindowId(winid_FavoriteName, (XP_WINDOW)this);
	}
}

