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
 * FavoriteManagerDlg type definition
 */

IMPLEMENT_DYNAMIC_CLASS( FavoriteManagerDlg, wxDialog )

wxDEFINE_EVENT(tsInternalUpdate, wxCommandEvent);

/*
 * FavoriteManagerDlg event table definition
 */

BEGIN_EVENT_TABLE( FavoriteManagerDlg, wxDialog )

////@begin FavoriteManagerDlg event table entries
    EVT_INIT_DIALOG( FavoriteManagerDlg::OnInitDialog )
    EVT_LISTBOX( ID_FAVORITE_LIST, FavoriteManagerDlg::OnFavoriteListSelected )
    EVT_LISTBOX_DCLICK( ID_FAVORITE_LIST, FavoriteManagerDlg::OnFavoriteListDoubleClicked )
    EVT_BUTTON( ID_ADD_FAVORITE, FavoriteManagerDlg::OnAddFavoriteClick )
    EVT_BUTTON( ID_EDIT_FAVORITE, FavoriteManagerDlg::OnEditFavoriteClick )
    EVT_BUTTON( ID_DELETEFAVORITE, FavoriteManagerDlg::OnDeletefavoriteClick )
    EVT_BUTTON( ID_RENAMEFAVORITE, FavoriteManagerDlg::OnRenamefavoriteClick )
    EVT_BUTTON( wxID_HELP, FavoriteManagerDlg::OnHelpClick )
////@end FavoriteManagerDlg event table entries

	EVT_COMMAND(wxID_ANY, tsInternalUpdate, FavoriteManagerDlg::OnFavChanges)

END_EVENT_TABLE()


/*
 * FavoriteManagerDlg constructors
 */

FavoriteManagerDlg::FavoriteManagerDlg()
{
    Init();
}

FavoriteManagerDlg::FavoriteManagerDlg( wxWindow* parent, wxWindowID id, const wxString& caption, const wxPoint& pos, const wxSize& size, long style )
{
    Init();
    Create(parent, id, caption, pos, size, style);
}


/*
 * FavoriteManagerDlg creator
 */

bool FavoriteManagerDlg::Create( wxWindow* parent, wxWindowID id, const wxString& caption, const wxPoint& pos, const wxSize& size, long style )
{
////@begin FavoriteManagerDlg creation
    SetExtraStyle(wxWS_EX_VALIDATE_RECURSIVELY|wxWS_EX_BLOCK_EVENTS);
    wxDialog::Create( parent, id, caption, pos, size, style );

    CreateControls();
    Centre();
////@end FavoriteManagerDlg creation
    return true;
}


/*
 * FavoriteManagerDlg destructor
 */

FavoriteManagerDlg::~FavoriteManagerDlg()
{
////@begin FavoriteManagerDlg destruction
////@end FavoriteManagerDlg destruction
}


/*
 * Member initialisation
 */

void FavoriteManagerDlg::Init()
{
////@begin FavoriteManagerDlg member initialisation
    _lstFavorites = NULL;
    _btnAdd = NULL;
    _btnEdit = NULL;
    _btnDelete = NULL;
    _btnRename = NULL;
////@end FavoriteManagerDlg member initialisation
}


/*
 * Control creation for FavoriteManagerDlg
 */

void FavoriteManagerDlg::CreateControls()
{    
////@begin FavoriteManagerDlg content construction
    FavoriteManagerDlg* itemDialog1 = this;

    wxFlexGridSizer* itemFlexGridSizer2 = new wxFlexGridSizer(0, 1, 0, 0);
    itemDialog1->SetSizer(itemFlexGridSizer2);

    wxStaticText* itemStaticText3 = new wxStaticText( itemDialog1, wxID_STATIC, _("This screen is used to manage the list of favorites that are available."), wxDefaultPosition, wxDefaultSize, 0 );
    itemFlexGridSizer2->Add(itemStaticText3, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    itemFlexGridSizer2->Add(5, 5, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    wxStaticText* itemStaticText5 = new wxStaticText( itemDialog1, wxID_STATIC, _("List of favorites:"), wxDefaultPosition, wxDefaultSize, 0 );
    itemFlexGridSizer2->Add(itemStaticText5, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    wxArrayString _lstFavoritesStrings;
    _lstFavorites = new wxListBox( itemDialog1, ID_FAVORITE_LIST, wxDefaultPosition, wxDefaultSize, _lstFavoritesStrings, wxLB_SINGLE );
    if (FavoriteManagerDlg::ShowToolTips())
        _lstFavorites->SetToolTip(_("This list contains all of the favorites saved in VEIL"));
    itemFlexGridSizer2->Add(_lstFavorites, 0, wxGROW|wxALL, 5);

    wxFlexGridSizer* itemFlexGridSizer7 = new wxFlexGridSizer(1, 6, 0, 0);
    itemFlexGridSizer2->Add(itemFlexGridSizer7, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    itemFlexGridSizer7->Add(5, 5, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    _btnAdd = new wxButton( itemDialog1, ID_ADD_FAVORITE, _("Add..."), wxDefaultPosition, wxDefaultSize, 0 );
    if (FavoriteManagerDlg::ShowToolTips())
        _btnAdd->SetToolTip(_("Create a new favorite"));
    itemFlexGridSizer7->Add(_btnAdd, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    _btnEdit = new wxButton( itemDialog1, ID_EDIT_FAVORITE, _("Edit..."), wxDefaultPosition, wxDefaultSize, 0 );
    if (FavoriteManagerDlg::ShowToolTips())
        _btnEdit->SetToolTip(_("Edit the currently selected favorite."));
    itemFlexGridSizer7->Add(_btnEdit, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxRIGHT|wxTOP|wxBOTTOM, 5);

    _btnDelete = new wxButton( itemDialog1, ID_DELETEFAVORITE, _("Delete"), wxDefaultPosition, wxDefaultSize, 0 );
    if (FavoriteManagerDlg::ShowToolTips())
        _btnDelete->SetToolTip(_("Delete the currently selected favorite"));
    itemFlexGridSizer7->Add(_btnDelete, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxRIGHT|wxTOP|wxBOTTOM, 5);

    _btnRename = new wxButton( itemDialog1, ID_RENAMEFAVORITE, _("Rename..."), wxDefaultPosition, wxDefaultSize, 0 );
    if (FavoriteManagerDlg::ShowToolTips())
        _btnRename->SetToolTip(_("Change the name of the currently selected favorite."));
    itemFlexGridSizer7->Add(_btnRename, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxRIGHT|wxTOP|wxBOTTOM, 5);

    itemFlexGridSizer7->Add(5, 5, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    itemFlexGridSizer7->AddGrowableCol(0);
    itemFlexGridSizer7->AddGrowableCol(5);

    wxStdDialogButtonSizer* itemStdDialogButtonSizer14 = new wxStdDialogButtonSizer;

    itemFlexGridSizer2->Add(itemStdDialogButtonSizer14, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxALL, 5);
    wxButton* itemButton15 = new wxButton( itemDialog1, wxID_OK, _("&OK"), wxDefaultPosition, wxDefaultSize, 0 );
    itemButton15->SetDefault();
    itemStdDialogButtonSizer14->AddButton(itemButton15);

    wxButton* itemButton16 = new wxButton( itemDialog1, wxID_HELP, _("&Help"), wxDefaultPosition, wxDefaultSize, 0 );
    itemStdDialogButtonSizer14->AddButton(itemButton16);

    itemStdDialogButtonSizer14->Realize();

    itemFlexGridSizer2->AddGrowableRow(3);
    itemFlexGridSizer2->AddGrowableCol(0);

////@end FavoriteManagerDlg content construction
}


/*
 * Should we show tooltips?
 */

bool FavoriteManagerDlg::ShowToolTips()
{
    return true;
}

/*
 * Get bitmap resources
 */

wxBitmap FavoriteManagerDlg::GetBitmapResource( const wxString& name )
{
	return ::GetBitmapResource(name);
}

/*
 * Get icon resources
 */

wxIcon FavoriteManagerDlg::GetIconResource( const wxString& name )
{
    // Icon retrieval
////@begin FavoriteManagerDlg icon retrieval
    wxUnusedVar(name);
    return wxNullIcon;
////@end FavoriteManagerDlg icon retrieval
}


/*
 * wxEVT_COMMAND_LISTBOX_SELECTED event handler for ID_FAVORITE_LIST
 */

void FavoriteManagerDlg::OnFavoriteListSelected( wxCommandEvent& event )
{
	updateControls();
}


/*
 * wxEVT_COMMAND_LISTBOX_DOUBLECLICKED event handler for ID_FAVORITE_LIST
 */

void FavoriteManagerDlg::OnFavoriteListDoubleClicked( wxCommandEvent& event )
{
	OnEditFavoriteClick(event);
}


void FavoriteManagerDlg::setVariables(audienceSelector2Variables* inVars)
{
	_vars = inVars;
}

void FavoriteManagerDlg::ReloadFavorites()
{
	wxQueueEvent(this, new wxCommandEvent(tsInternalUpdate));
}

void FavoriteManagerDlg::updateControls()
{
	if (_vars == nullptr || !_vars->_connector || !_vars->_connector->isConnected())
	{
		_btnAdd->Enable(false);
		_btnEdit->Enable(false);
		_btnDelete->Enable(false);
		_btnRename->Enable(false);
		_lstFavorites->Enable(false);
	}
	else
	{
		_lstFavorites->Enable(true);
		_btnAdd->Enable(true);
		_btnEdit->Enable(_lstFavorites->GetSelection() >= 0);
		_btnDelete->Enable(_lstFavorites->GetSelection() >= 0);
		_btnRename->Enable(_lstFavorites->GetSelection() >= 0);
	}
}

/*
 * wxEVT_INIT_DIALOG event handler for ID_FAVORITEMANAGERDLG
 */

void FavoriteManagerDlg::OnInitDialog( wxInitDialogEvent& event )
{
	if (_vars != nullptr)
	{
		wxCommandEvent evt;
		OnFavChanges(evt);
	}
    event.Skip();
}


/*
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_ADD_FAVORITE
 */

void FavoriteManagerDlg::OnAddFavoriteClick( wxCommandEvent& event )
{
	if (_vars == nullptr)
	{
		wxTsMessageBox("The system has not been initialized.", "ERROR", wxOK | wxICON_HAND);
		return;
	}

	// Construct the dialog here
	AudienceSelector2 dlg;
	_vars->_favoriteId = GUID_NULL;
	_vars->_favoriteManager = true;
	_vars->_favoriteName.clear();
	_vars->_header = ::TopServiceLocator()->get_instance<ICmsHeader>("/CmsHeader");

	dlg.setVariables(_vars);

	dlg.Create(this);

	dlg.Run() ? wxID_OK : wxID_CANCEL;
	updateControls();
}


/*
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_EDIT_FAVORITE
 */

void FavoriteManagerDlg::OnEditFavoriteClick( wxCommandEvent& event )
{
	if (_vars == nullptr || !_vars->_connector || !_vars->_connector->isConnected())
	{
		wxTsMessageBox("The system has not been initialized.", "ERROR", wxOK | wxICON_HAND);
		return;
	}

	if (_lstFavorites->GetSelection() < 0)
		return;

	std::shared_ptr<IFavorite> fav = _vars->_connector->favorite(_lstFavorites->GetString(_lstFavorites->GetSelection()).mbc_str().data());

	if (!fav)
	{
		wxTsMessageBox("The selected favorite is no longer available.", "ERROR", wxOK | wxICON_HAND);
		wxQueueEvent(this, new wxCommandEvent(tsInternalUpdate));
		return;
	}

	// Construct the dialog here
	AudienceSelector2 dlg;
	_vars->_favoriteId = fav->favoriteId();
	_vars->_favoriteManager = true;
	_vars->_favoriteName = fav->favoriteName();
	if (!_vars->_header)
		_vars->_header = ::TopServiceLocator()->get_instance<ICmsHeader>("/CmsHeader");
	_vars->_header->Clear();
	_vars->_header->FromBytes(fav->headerData());

	dlg.setVariables(_vars);

	dlg.Create(this);

	dlg.Run() ? wxID_OK : wxID_CANCEL;
	updateControls();
}


/*
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_DELETEFAVORITE
 */

void FavoriteManagerDlg::OnDeletefavoriteClick( wxCommandEvent& event )
{
	if (_vars == nullptr || !_vars->_connector || !_vars->_connector->isConnected())
	{
		wxTsMessageBox("The system has not been initialized.", "ERROR", wxOK | wxICON_HAND);
		return;
	}

	if (_lstFavorites->GetSelection() < 0)
		return;

	std::shared_ptr<IFavorite> fav = _vars->_connector->favorite(_lstFavorites->GetString(_lstFavorites->GetSelection()).mbc_str().data());

	if (!fav)
	{
		wxTsMessageBox("The selected favorite is no longer available.", "ERROR", wxOK | wxICON_HAND);
		wxQueueEvent(this, new wxCommandEvent(tsInternalUpdate));
		return;
	}

	if (wxTsMessageBox("Are you sure that you want to delete this favorite?  This process cannot be reversed.", "Question", wxYES_NO | wxICON_EXCLAMATION, (XP_WINDOW)this) == wxYES)
	{
		_vars->_connector->DeleteFavorite(fav->favoriteId());
		updateControls();
	}
}


/*
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_RENAMEFAVORITE
 */

void FavoriteManagerDlg::OnRenamefavoriteClick( wxCommandEvent& event )
{
	if (_vars == nullptr || !_vars->_connector || !_vars->_connector->isConnected())
	{
		wxTsMessageBox("The system has not been initialized.", "ERROR", wxOK | wxICON_HAND);
		return;
	}

	if (_lstFavorites->GetSelection() < 0)
		return;

	std::shared_ptr<IFavorite> fav = _vars->_connector->favorite(_lstFavorites->GetString(_lstFavorites->GetSelection()).mbc_str().data());

	if (!fav)
	{
		wxTsMessageBox("The selected favorite is no longer available.", "ERROR", wxOK | wxICON_HAND);
		wxQueueEvent(this, new wxCommandEvent(tsInternalUpdate));
		return;
	}

	ChangeNameDlg dlg;

	dlg.Create(this);
	dlg.SetOldName(fav->favoriteName());
	dlg.SetNewName(fav->favoriteName());
	dlg.helpId = winid_ChangeFavoriteName;
	dlg.SetDescription("Enter the new name for this favorite.");

	if (dlg.ShowModal() == wxID_OK)
	{
		fav->favoriteName(dlg.GetNewName());
		if (_vars->_connector->UpdateFavoriteName(fav->favoriteId(), dlg.GetNewName()))
		{
			wxTsMessageBox("The favorite has been renamed.", "Success", wxOK);
		}
	}
}

void FavoriteManagerDlg::OnFavChanges(wxCommandEvent& event)
{
	if (_vars != nullptr && !!_vars->_connector && _vars->_connector->isConnected())
	{
		size_t count = _vars->_connector->favoriteCount();

		_lstFavorites->Clear();
		for (size_t i = 0; i < count; i++)
		{
			std::shared_ptr<IFavorite> fav = _vars->_connector->favorite(i);

			if (!!fav)
			{
				_lstFavorites->Append(fav->favoriteName().c_str());
			}
		}
	}
	updateControls();
}


/*
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_HELP
 */

void FavoriteManagerDlg::OnHelpClick( wxCommandEvent& event )
{
	std::shared_ptr<IVEILHttpHelpRegistry> help = ::TopServiceLocator()->get_instance<IVEILHttpHelpRegistry>("/WxWin/HelpRegistry");

	if (!help)
	{
		wxTsMessageBox(("Help is not available at this time."), ("Status"), wxOK);
	}
	else
	{
		help->DisplayHelpForWindowId(winid_FavoriteManager, (XP_WINDOW)this);
	}
}

