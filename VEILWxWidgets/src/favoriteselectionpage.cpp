/////////////////////////////////////////////////////////////////////////////
// Name:        favoriteselectionpage.cpp
// Purpose:     
// Author:      Roger Butler
// Modified by: 
// Created:     13/02/2017 16:04:06
// RCS-ID:      
// Copyright:   Copyright (c) 2017, TecSec, Inc.  
// Licence:     
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx/wx.h".
#include "stdafx.h"

////@begin includes
////@end includes

////@begin XPM images
////@end XPM images


/*
 * FavoriteSelectionPage type definition
 */

IMPLEMENT_DYNAMIC_CLASS( FavoriteSelectionPage, wxWizardPage )


/*
 * FavoriteSelectionPage event table definition
 */

BEGIN_EVENT_TABLE( FavoriteSelectionPage, wxWizardPage )

////@begin FavoriteSelectionPage event table entries
    EVT_WIZARD_PAGE_CHANGED( -1, FavoriteSelectionPage::OnFavoriteSelectionPagePageChanged )
    EVT_WIZARD_PAGE_CHANGING( -1, FavoriteSelectionPage::OnFavoriteSelectionPagePageChanging )
    EVT_WIZARD_FINISHED( ID_FAVORITE_SELECTION_PAGE, FavoriteSelectionPage::OnFavoriteSelectionPageFinished )
    EVT_WIZARD_HELP( -1, FavoriteSelectionPage::OnFavoriteSelectionPageHelp )
    EVT_CHOICE( ID_CHOICE, FavoriteSelectionPage::OnChoiceSelected )
////@end FavoriteSelectionPage event table entries

END_EVENT_TABLE()


/*
 * FavoriteSelectionPage constructors
 */

FavoriteSelectionPage::FavoriteSelectionPage() : nextPage(nullptr), prevPage(nullptr)
{
    Init();
}

FavoriteSelectionPage::FavoriteSelectionPage( wxWizard* parent ) : nextPage(nullptr), prevPage(nullptr)
{
    Init();
    Create( parent );
}


/*
 * FavoriteSelectionPage creator
 */

bool FavoriteSelectionPage::Create( wxWizard* parent )
{
////@begin FavoriteSelectionPage creation
    SetExtraStyle(wxWS_EX_VALIDATE_RECURSIVELY);
    wxBitmap wizardBitmap(wxNullBitmap);
    wxWizardPage::Create( parent, wizardBitmap );

    CreateControls();
    if (GetSizer())
        GetSizer()->Fit(this);
////@end FavoriteSelectionPage creation
    return true;
}


/*
 * FavoriteSelectionPage destructor
 */

FavoriteSelectionPage::~FavoriteSelectionPage()
{
////@begin FavoriteSelectionPage destruction
////@end FavoriteSelectionPage destruction
}


/*
 * Member initialisation
 */

void FavoriteSelectionPage::Init()
{
////@begin FavoriteSelectionPage member initialisation
    _cmbFavorites = NULL;
////@end FavoriteSelectionPage member initialisation
}


/*
 * Control creation for FavoriteSelectionPage
 */

void FavoriteSelectionPage::CreateControls()
{    
////@begin FavoriteSelectionPage content construction
    FavoriteSelectionPage* itemWizardPage1 = this;

    wxBoxSizer* itemBoxSizer2 = new wxBoxSizer(wxVERTICAL);
    itemWizardPage1->SetSizer(itemBoxSizer2);

    wxStaticText* itemStaticText3 = new wxStaticText( itemWizardPage1, wxID_STATIC, _("Select a Favorite"), wxDefaultPosition, wxDefaultSize, 0 );
    itemStaticText3->SetFont(wxFont(8, wxFONTFAMILY_SWISS, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_BOLD, false, wxT("Tahoma")));
    itemBoxSizer2->Add(itemStaticText3, 0, wxALIGN_LEFT|wxALL, 5);

    wxStaticText* itemStaticText4 = new wxStaticText( itemWizardPage1, wxID_STATIC, _("Select a favorite or continue on to manually specify the encryption parameters."), wxDefaultPosition, wxDefaultSize, 0 );
    itemBoxSizer2->Add(itemStaticText4, 0, wxALIGN_LEFT|wxALL, 5);

    itemBoxSizer2->Add(5, 5, 0, wxALIGN_CENTER_HORIZONTAL|wxALL, 5);

    wxStaticText* itemStaticText6 = new wxStaticText( itemWizardPage1, wxID_STATIC, _("Favorite to use:"), wxDefaultPosition, wxDefaultSize, 0 );
    itemBoxSizer2->Add(itemStaticText6, 0, wxALIGN_LEFT|wxALL, 5);

    wxArrayString _cmbFavoritesStrings;
    _cmbFavoritesStrings.Add(_("<Manually enter>"));
    _cmbFavorites = new wxChoice( itemWizardPage1, ID_CHOICE, wxDefaultPosition, wxDefaultSize, _cmbFavoritesStrings, 0 );
    _cmbFavorites->SetStringSelection(_("<Manually enter>"));
    if (FavoriteSelectionPage::ShowToolTips())
        _cmbFavorites->SetToolTip(_("Either select a favorite from this list or use <Manually enter> to create an ad-hoc encryption recipe."));
    itemBoxSizer2->Add(_cmbFavorites, 0, wxGROW|wxALL, 5);

////@end FavoriteSelectionPage content construction
}


/*
 * Gets the previous page.
 */

wxWizardPage* FavoriteSelectionPage::GetPrev() const
{
	ISkippablePage* tokPg = dynamic_cast<ISkippablePage*>(prevPage);

	if (tokPg != nullptr && tokPg->skipMe())
		return prevPage->GetPrev();
    return prevPage;
}


/*
 * Gets the next page.
 */

wxWizardPage* FavoriteSelectionPage::GetNext() const
{
	ISkippablePage* tokPg = dynamic_cast<ISkippablePage*>(nextPage);

	if (tokPg != nullptr && tokPg->skipMe())
		return nextPage->GetNext();
	return nextPage;
}


/*
 * Should we show tooltips?
 */

bool FavoriteSelectionPage::ShowToolTips()
{
    return true;
}

bool FavoriteSelectionPage::skipMe()
{
	AudienceSelector2* wiz = dynamic_cast<AudienceSelector2*>(GetParent());

	if (wiz == nullptr || wiz->_vars == nullptr)
		return false;

	return wiz->_vars->_favoriteManager;
}

/*
 * Get bitmap resources
 */

wxBitmap FavoriteSelectionPage::GetBitmapResource( const wxString& name )
{
    // Bitmap retrieval
////@begin FavoriteSelectionPage bitmap retrieval
    wxUnusedVar(name);
    return wxNullBitmap;
////@end FavoriteSelectionPage bitmap retrieval
}

/*
 * Get icon resources
 */

wxIcon FavoriteSelectionPage::GetIconResource( const wxString& name )
{
    // Icon retrieval
////@begin FavoriteSelectionPage icon retrieval
    wxUnusedVar(name);
    return wxNullIcon;
////@end FavoriteSelectionPage icon retrieval
}


/*
 * wxEVT_WIZARD_PAGE_CHANGED event handler for ID_FAVORITE_SELECTION_PAGE
 */

void FavoriteSelectionPage::OnFavoriteSelectionPagePageChanged( wxWizardEvent& event )
{
	AudienceSelector2* wiz = dynamic_cast<AudienceSelector2*>(GetParent());

    event.Skip();
	FindWindowById(wxID_FORWARD, this->GetParent())->Enable(true);
	_cmbFavorites->Clear();

	if (wiz != nullptr && wiz->_vars != nullptr)
	{
		GUID id = GUID_NULL;

		if (!!wiz->_vars->_session && !!!wiz->_vars->_session->HasProfile())
		{
			wxBusyCursor busyCursor;
			wxWindowDisabler disabler;
			wxBusyInfo busyInfo(_("Retrieving token information..."));

			!!wiz->_vars->_session->GetProfile();
		}

		if (!!wiz->_vars->_session && !!wiz->_vars->_session->GetProfile())
			id = wiz->_vars->_session->GetProfile()->get_EnterpriseId();

		for (size_t i = 0; i < wiz->_vars->_connector->favoriteCountForEnterprise(id); i++)
		{
			_cmbFavorites->AppendString(wiz->_vars->_connector->favoriteForEnterprise(id, i)->favoriteName().c_str());
		}
	}

	_cmbFavorites->Insert("<Manually enter>", 0);
	if (!wiz->_vars->_favoriteName.empty())
	{
		_cmbFavorites->SetSelection(_cmbFavorites->FindString(wiz->_vars->_favoriteName.c_str()));
		if (_cmbFavorites->GetSelection() < 0)
			_cmbFavorites->SetSelection(0);
	}
	else
		_cmbFavorites->SetSelection(0);
}


/*
 * wxEVT_WIZARD_PAGE_CHANGING event handler for ID_FAVORITE_SELECTION_PAGE
 */

void FavoriteSelectionPage::OnFavoriteSelectionPagePageChanging( wxWizardEvent& event )
{
	AudienceSelector2* wiz = dynamic_cast<AudienceSelector2*>(GetParent());

	event.Skip();
	FindWindowById(wxID_FORWARD, this->GetParent())->Enable(true);

	if (wiz == nullptr || wiz->_vars == nullptr || !wiz->_vars->_connector ||  !event.GetDirection())
		return;
	if (_cmbFavorites->GetSelection() >= 1)
	{
		wiz->_vars->_favoriteId = GUID_NULL;
		wiz->_vars->_favoriteName = _cmbFavorites->GetString(_cmbFavorites->GetSelection()).mbc_str().data();
		std::shared_ptr<IFavorite> fav = wiz->_vars->_connector->favorite(wiz->_vars->_favoriteName);

		if (!!fav)
		{
			wiz->_vars->_favoriteId = fav->favoriteId();
			if (!wiz->_vars->_header)
			{
				wiz->_vars->_header = ::TopServiceLocator()->get_instance<ICmsHeader>("/CmsHeader");
			}
			wiz->_vars->_header->FromBytes(fav->headerData());
		}
		else
		{
			wxTsMessageBox("The favorite is not available.", "ERROR", wxOK);
			event.Veto();
		}
	}
}


/*
 * wxEVT_WIZARD_FINISHED event handler for ID_FAVORITE_SELECTION_PAGE
 */

void FavoriteSelectionPage::OnFavoriteSelectionPageFinished( wxWizardEvent& event )
{
////@begin wxEVT_WIZARD_FINISHED event handler for ID_FAVORITE_SELECTION_PAGE in FavoriteSelectionPage.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_WIZARD_FINISHED event handler for ID_FAVORITE_SELECTION_PAGE in FavoriteSelectionPage. 
}


/*
 * wxEVT_WIZARD_HELP event handler for ID_FAVORITE_SELECTION_PAGE
 */

void FavoriteSelectionPage::OnFavoriteSelectionPageHelp( wxWizardEvent& event )
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

		}
		else if (wiz != nullptr && wiz->_vars != nullptr && wiz->_vars->_favoriteManager)
		{

		}
		else
			help->DisplayHelpForWindowId(winid_FavoriteSelectionPage, (XP_WINDOW)this);
	}
}


/*
 * wxEVT_COMMAND_CHOICE_SELECTED event handler for ID_CHOICE
 */

void FavoriteSelectionPage::OnChoiceSelected( wxCommandEvent& event )
{
	AudienceSelector2* wiz = dynamic_cast<AudienceSelector2*>(GetParent());

    event.Skip();
	if (wiz == nullptr)
		return;
	if (_cmbFavorites->GetSelection() < 1)
	{
		SetNextPage(wiz->_accessGroupPage);
		wiz->setupLeftPanel();
	}
	else
	{
		SetNextPage(nullptr);
		wiz->setupLeftPanel();
	}
}

