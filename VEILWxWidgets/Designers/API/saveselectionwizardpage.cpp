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
 * SaveSelectionWizardPage type definition
 */

IMPLEMENT_DYNAMIC_CLASS( SaveSelectionWizardPage, wxWizardPageSimple )


/*
 * SaveSelectionWizardPage event table definition
 */

BEGIN_EVENT_TABLE( SaveSelectionWizardPage, wxWizardPageSimple )

////@begin SaveSelectionWizardPage event table entries
    EVT_WIZARD_PAGE_CHANGED( -1, SaveSelectionWizardPage::OnSaveFavoritePageChanged )
    EVT_WIZARD_PAGE_CHANGING( -1, SaveSelectionWizardPage::OnSaveFavoritePageChanging )
    EVT_WIZARD_FINISHED( ID_SAVE_FAVORITE, SaveSelectionWizardPage::OnSaveFavoriteFinished )
    EVT_WIZARD_HELP( -1, SaveSelectionWizardPage::OnSaveFavoriteHelp )
    EVT_TEXT( ID_TEXTCTRL1, SaveSelectionWizardPage::OnTextctrl1TextUpdated )
    EVT_BUTTON( ID_SAVE, SaveSelectionWizardPage::OnSaveClick )
////@end SaveSelectionWizardPage event table entries

END_EVENT_TABLE()


/*
 * SaveSelectionWizardPage constructors
 */

SaveSelectionWizardPage::SaveSelectionWizardPage() : nextPage(nullptr), prevPage(nullptr)
{
    Init();
}

SaveSelectionWizardPage::SaveSelectionWizardPage( wxWizard* parent ) : nextPage(nullptr), prevPage(nullptr)
{
    Init();
    Create( parent );
}


/*
 * SaveSelectionWizardPage creator
 */

bool SaveSelectionWizardPage::Create( wxWizard* parent )
{
	AudienceSelector2* wiz = dynamic_cast<AudienceSelector2*>(parent);

	////@begin SaveSelectionWizardPage creation
    SetExtraStyle(wxWS_EX_VALIDATE_RECURSIVELY);
    wxBitmap wizardBitmap(wxNullBitmap);
    wxWizardPage::Create( parent, wizardBitmap );

    CreateControls();
    if (GetSizer())
        GetSizer()->Fit(this);
////@end SaveSelectionWizardPage creation
	updateControls();
	if (wiz != nullptr && wiz->_vars != nullptr && wiz->_vars->_favoriteManager)
	{
		_lblOptional->Hide();
		_btnSave->Show(!wiz->_vars->_favoriteName.empty());
	}
    return true;
}


/*
 * SaveSelectionWizardPage destructor
 */

SaveSelectionWizardPage::~SaveSelectionWizardPage()
{
////@begin SaveSelectionWizardPage destruction
////@end SaveSelectionWizardPage destruction
}


/*
 * Member initialisation
 */

void SaveSelectionWizardPage::Init()
{
////@begin SaveSelectionWizardPage member initialisation
    _lblOptional = NULL;
    _txtFavoriteName = NULL;
    _btnSave = NULL;
////@end SaveSelectionWizardPage member initialisation
}


/*
 * Control creation for SaveSelectionWizardPage
 */

void SaveSelectionWizardPage::CreateControls()
{    
////@begin SaveSelectionWizardPage content construction
    SaveSelectionWizardPage* itemWizardPage1 = this;

    wxBoxSizer* itemBoxSizer2 = new wxBoxSizer(wxVERTICAL);
    itemWizardPage1->SetSizer(itemBoxSizer2);

    wxStaticText* itemStaticText3 = new wxStaticText( itemWizardPage1, wxID_STATIC, _("Save Selection"), wxDefaultPosition, wxDefaultSize, 0 );
    itemStaticText3->SetFont(wxFont(8, wxFONTFAMILY_SWISS, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_BOLD, false, wxT("Tahoma")));
    itemBoxSizer2->Add(itemStaticText3, 0, wxALIGN_LEFT|wxALL, 5);

    wxStaticText* itemStaticText4 = new wxStaticText( itemWizardPage1, wxID_STATIC, _("In this step you have the option to save this selection for later use as a new favorite."), wxDefaultPosition, wxDefaultSize, 0 );
    itemBoxSizer2->Add(itemStaticText4, 0, wxALIGN_LEFT|wxALL, 5);

    _lblOptional = new wxStaticText( itemWizardPage1, wxID_STATIC, _("This step is optional."), wxDefaultPosition, wxDefaultSize, 0 );
    itemBoxSizer2->Add(_lblOptional, 0, wxALIGN_LEFT|wxALL, 5);

    itemBoxSizer2->Add(5, 5, 0, wxALIGN_CENTER_HORIZONTAL|wxALL, 5);

    wxStaticText* itemStaticText7 = new wxStaticText( itemWizardPage1, wxID_STATIC, _("Name:"), wxDefaultPosition, wxDefaultSize, 0 );
    itemBoxSizer2->Add(itemStaticText7, 0, wxALIGN_LEFT|wxALL, 5);

    _txtFavoriteName = new wxTextCtrl( itemWizardPage1, ID_TEXTCTRL1, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
    _txtFavoriteName->SetMaxLength(100);
    if (SaveSelectionWizardPage::ShowToolTips())
        _txtFavoriteName->SetToolTip(_("Enter the name of the favorite that you want to create using this recipe."));
    itemBoxSizer2->Add(_txtFavoriteName, 0, wxGROW|wxALL, 5);

    wxFlexGridSizer* itemFlexGridSizer9 = new wxFlexGridSizer(1, 3, 0, 0);
    itemBoxSizer2->Add(itemFlexGridSizer9, 0, wxGROW|wxALL, 5);

    itemFlexGridSizer9->Add(5, 5, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    _btnSave = new wxButton( itemWizardPage1, ID_SAVE, _("Save New Favorite"), wxDefaultPosition, wxDefaultSize, 0 );
    if (SaveSelectionWizardPage::ShowToolTips())
        _btnSave->SetToolTip(_("Press this button to save this recipe as a favorite."));
    itemFlexGridSizer9->Add(_btnSave, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    itemFlexGridSizer9->Add(5, 5, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    itemFlexGridSizer9->AddGrowableCol(0);
    itemFlexGridSizer9->AddGrowableCol(2);

////@end SaveSelectionWizardPage content construction
}


/*
 * wxEVT_WIZARD_PAGE_CHANGED event handler for ID_SAVE_FAVORITE
 */

void SaveSelectionWizardPage::OnSaveFavoritePageChanged( wxWizardEvent& event )
{
	updateControls();
    event.Skip();
}


/*
 * wxEVT_WIZARD_PAGE_CHANGING event handler for ID_SAVE_FAVORITE
 */

void SaveSelectionWizardPage::OnSaveFavoritePageChanging( wxWizardEvent& event )
{
	AudienceSelector2* wiz = dynamic_cast<AudienceSelector2*>(GetParent());

	if (!event.GetDirection())
	{
		event.Skip();
		return;
	}

	if (wiz != nullptr && wiz->_vars != nullptr && wiz->_vars->_favoriteManager && !wiz->_vars->_favoriteName.empty() && event.GetDirection())
	{
		if (!wiz->_vars->_connector->UpdateFavorite(wiz->_vars->_favoriteId, wiz->_vars->_header->ToBytes()))
		{
			wxTsMessageBox("An error has occurred while updating the favorite.", "Error", wxICON_HAND | wxOK);
			return;
		}
		else
		{
			wxTsMessageBox("The favorite has been updated.", "Updated", wxOK);
			_txtFavoriteName->SetValue("");
			updateControls();
		}
	}
	else if (wiz != nullptr && wiz->_vars != nullptr && wiz->_vars->_favoriteManager && wiz->_vars->_favoriteName.empty())
	{
		tsCryptoString favName = _txtFavoriteName->GetValue().mbc_str().data();

		if (!!wiz->_vars->_session && wiz->_vars->_session->GetProfile()->exists_SerialNumber())
			wiz->_vars->_favoriteId = wiz->_vars->_connector->CreateFavorite(*wiz->_vars->_session->GetProfile()->get_SerialNumber(), wiz->_vars->_header->ToBytes(), favName);
		else
			wiz->_vars->_favoriteId = wiz->_vars->_connector->CreateFavorite(tsCryptoData(), wiz->_vars->_header->ToBytes(), favName);
		if (wiz->_vars->_favoriteId == GUID_NULL)
		{
			wxTsMessageBox("An error occurred while attempting to create the new favorite.", "Error", wxICON_HAND | wxOK);
			event.Veto();
			return;
		}
		else
		{
			wxTsMessageBox("The favorite has been saved.", "Success", wxICON_INFORMATION | wxOK);
			_txtFavoriteName->SetValue("");
			updateControls();
			event.Skip();
			return;
		}
	}
	else
    event.Skip();
}


/*
 * wxEVT_WIZARD_FINISHED event handler for ID_SAVE_FAVORITE
 */

void SaveSelectionWizardPage::OnSaveFavoriteFinished( wxWizardEvent& event )
{
////@begin wxEVT_WIZARD_FINISHED event handler for ID_SAVE_FAVORITE in SaveSelectionWizardPage.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_WIZARD_FINISHED event handler for ID_SAVE_FAVORITE in SaveSelectionWizardPage. 
}


/*
 * wxEVT_WIZARD_HELP event handler for ID_SAVE_FAVORITE
 */

void SaveSelectionWizardPage::OnSaveFavoriteHelp( wxWizardEvent& event )
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
			help->DisplayHelpForWindowId(winid_FavEdit_SaveFavoritePage, (XP_WINDOW)this);
		}
		else if (wiz != nullptr && wiz->_vars != nullptr && wiz->_vars->_favoriteManager)
		{
			help->DisplayHelpForWindowId(winid_FavAdd_SaveFavoritePage, (XP_WINDOW)this);
		}
		else
		help->DisplayHelpForWindowId(winid_SaveFavoritePage, (XP_WINDOW)this);
	}
}


/*
 * wxEVT_COMMAND_TEXT_UPDATED event handler for ID_TEXTCTRL1
 */

void SaveSelectionWizardPage::OnTextctrl1TextUpdated( wxCommandEvent& event )
{
	updateControls();
}


/*
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_SAVE
 */

void SaveSelectionWizardPage::OnSaveClick( wxCommandEvent& event )
{
	tsCryptoString favName = _txtFavoriteName->GetValue().mbc_str().data();
	AudienceSelector2* wiz = dynamic_cast<AudienceSelector2*>(GetParent());

	favName.Trim();

	if (wiz != nullptr && wiz->_vars != nullptr && ((wiz->_vars->_favoriteId == GUID_NULL || !wiz->_vars->_favoriteManager) || (wiz->_vars->_favoriteManager && !favName.empty())))
	{
		if (!!wiz->_vars->_session && wiz->_vars->_session->GetProfile()->exists_SerialNumber())
			wiz->_vars->_favoriteId = wiz->_vars->_connector->CreateFavorite(*wiz->_vars->_session->GetProfile()->get_SerialNumber(), wiz->_vars->_header->ToBytes(), favName);
		else
			wiz->_vars->_favoriteId = wiz->_vars->_connector->CreateFavorite(tsCryptoData(), wiz->_vars->_header->ToBytes(), favName);
		if (wiz->_vars->_favoriteId == GUID_NULL)
	{
			wxTsMessageBox("An error occurred while attempting to create the new favorite.", "Error", wxICON_HAND | wxOK);
		return;
	}
		else
		{
			wxTsMessageBox("The favorite has been saved.", "Success", wxICON_INFORMATION | wxOK);
			_txtFavoriteName->SetValue("");
			updateControls();
			return;
		}
	}

	//if (id != GUID_NULL)
	//{
	//}
	//else
	//{
	//	wxTsMessageBox("The selected favorite could not be found.", "Error", wxICON_HAND | wxOK);
	//	return;
	//}

	return;
}


/*
 * Should we show tooltips?
 */

bool SaveSelectionWizardPage::ShowToolTips()
{
    return true;
}

/*
 * Get bitmap resources
 */

wxBitmap SaveSelectionWizardPage::GetBitmapResource( const wxString& name )
{
	return ::GetBitmapResource(name);
}

/*
 * Get icon resources
 */

wxIcon SaveSelectionWizardPage::GetIconResource( const wxString& name )
{
    // Icon retrieval
////@begin SaveSelectionWizardPage icon retrieval
    wxUnusedVar(name);
    return wxNullIcon;
////@end SaveSelectionWizardPage icon retrieval
}

void SaveSelectionWizardPage::updateControls()
{
	tsCryptoString favName = _txtFavoriteName->GetValue().mbc_str().data();
	AudienceSelector2* wiz = dynamic_cast<AudienceSelector2*>(GetParent());

	favName.Trim();
	_btnSave->Enable(wiz != nullptr && wiz->_vars != nullptr && !!wiz->_vars->_connector && !!wiz->_vars->_header && !favName.empty());
	if (wiz->_vars != nullptr && wiz->_vars->_favoriteManager && wiz->_vars->_favoriteName.empty())
	{
		FindWindowById(wxID_FORWARD, this->GetParent())->Enable(!_txtFavoriteName->GetValue().empty());
		if (!_txtFavoriteName->GetValue().empty())
		{
			((wxButton*)FindWindowById(wxID_FORWARD, this->GetParent()))->SetDefault();
		}
	}
	else if (wiz->_vars != nullptr && !!wiz->_vars->_connector && !!wiz->_vars->_header && !favName.empty())
		_btnSave->SetDefault();
	else
		((wxButton*)FindWindowById(wxID_FORWARD, this->GetParent()))->SetDefault();
}

bool SaveSelectionWizardPage::skipMe()
{
	return false;
}


/*
 * Gets the previous page.
 */

wxWizardPage* SaveSelectionWizardPage::GetPrev() const
{
	ISkippablePage* tokPg = dynamic_cast<ISkippablePage*>(prevPage);

	if (tokPg != nullptr && tokPg->skipMe())
		return prevPage->GetPrev();
    return prevPage;
}


/*
 * Gets the next page.
 */

wxWizardPage* SaveSelectionWizardPage::GetNext() const
{
	ISkippablePage* tokPg = dynamic_cast<ISkippablePage*>(nextPage);

	if (tokPg != nullptr && tokPg->skipMe())
		return nextPage->GetNext();
    return nextPage;
}

