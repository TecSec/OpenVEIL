/////////////////////////////////////////////////////////////////////////////
// Name:        audienceselector.cpp
// Purpose:     
// Author:      Roger Butler
// Modified by: 
// Created:     09/02/2016 13:05:32
// RCS-ID:      
// Copyright:   Copyright (c) 2016, TecSec, Inc.  
// Licence:     
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx/wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
#pragma hdrstop
#endif

#ifndef WX_PRECOMP
#include "wx/wx.h"
#endif

////@begin includes
////@end includes

#include "audienceselector.h"

////@begin XPM images
////@end XPM images


/*
 * AudienceSelector type definition
 */

IMPLEMENT_DYNAMIC_CLASS( AudienceSelector, wxDialog )


/*
 * AudienceSelector event table definition
 */

BEGIN_EVENT_TABLE( AudienceSelector, wxDialog )

////@begin AudienceSelector event table entries
    EVT_CHOICE( ID_FAVORITELIST, AudienceSelector::OnFavoritelistSelected )
    EVT_CHOICE( ID_TOKENLIST, AudienceSelector::OnTokenlistSelected )
    EVT_CHOICE( ID_CGLIST, AudienceSelector::OnCglistSelected )
    EVT_LISTBOX( ID_LISTBOX, AudienceSelector::OnListboxSelected )
    EVT_LISTBOX_DCLICK( ID_LISTBOX, AudienceSelector::OnListboxDoubleClicked )
    EVT_BUTTON( ID_ADD, AudienceSelector::OnAddClick )
    EVT_BUTTON( ID_EDIT, AudienceSelector::OnEditClick )
    EVT_BUTTON( ID_DELETE, AudienceSelector::OnDeleteClick )
    EVT_BUTTON( ID_CREATE_FAVORITE, AudienceSelector::OnCreateFavoriteClick )
    EVT_BUTTON( ID_DELETE_FAVORITE, AudienceSelector::OnDeleteFavoriteClick )
    EVT_BUTTON( wxID_OK, AudienceSelector::OnOkClick )
    EVT_BUTTON( wxID_CANCEL, AudienceSelector::OnCancelClick )
    EVT_BUTTON( wxID_HELP, AudienceSelector::OnHelpClick )
////@end AudienceSelector event table entries

END_EVENT_TABLE()


/*
 * AudienceSelector constructors
 */

AudienceSelector::AudienceSelector()
{
    Init();
}

AudienceSelector::AudienceSelector( wxWindow* parent, wxWindowID id, const wxString& caption, const wxPoint& pos, const wxSize& size, long style )
{
    Init();
    Create(parent, id, caption, pos, size, style);
}


/*
 * AudienceSelector creator
 */

bool AudienceSelector::Create( wxWindow* parent, wxWindowID id, const wxString& caption, const wxPoint& pos, const wxSize& size, long style )
{
////@begin AudienceSelector creation
    SetExtraStyle(wxWS_EX_VALIDATE_RECURSIVELY|wxWS_EX_BLOCK_EVENTS);
    wxDialog::Create( parent, id, caption, pos, size, style );

    CreateControls();
    if (GetSizer())
    {
        GetSizer()->SetSizeHints(this);
    }
    Centre();
////@end AudienceSelector creation
    return true;
}


/*
 * AudienceSelector destructor
 */

AudienceSelector::~AudienceSelector()
{
////@begin AudienceSelector destruction
////@end AudienceSelector destruction
}


/*
 * Member initialisation
 */

void AudienceSelector::Init()
{
////@begin AudienceSelector member initialisation
    cmbFavorites = NULL;
    cmbTokens = NULL;
    cmbCG = NULL;
    lstGroups = NULL;
    btnAdd = NULL;
    btnEdit = NULL;
    btnDelete = NULL;
    btnCreateFavorite = NULL;
    btnDeleteFavorite = NULL;
    btnOK = NULL;
    btnCancel = NULL;
    btnHelp = NULL;
////@end AudienceSelector member initialisation
}


/*
 * Control creation for AudienceSelector
 */

void AudienceSelector::CreateControls()
{    
////@begin AudienceSelector content construction
    AudienceSelector* itemDialog1 = this;

    wxFlexGridSizer* itemFlexGridSizer2 = new wxFlexGridSizer(3, 1, 0, 0);
    itemDialog1->SetSizer(itemFlexGridSizer2);

    wxFlexGridSizer* itemFlexGridSizer3 = new wxFlexGridSizer(0, 2, 0, 0);
    itemFlexGridSizer2->Add(itemFlexGridSizer3, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxALL, 0);

    wxStaticText* itemStaticText4 = new wxStaticText( itemDialog1, wxID_STATIC, _("Favorites:"), wxDefaultPosition, wxDefaultSize, 0 );
    itemFlexGridSizer3->Add(itemStaticText4, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxLEFT|wxRIGHT|wxTOP, 5);

    wxArrayString cmbFavoritesStrings;
    cmbFavorites = new wxChoice( itemDialog1, ID_FAVORITELIST, wxDefaultPosition, wxSize(400, -1), cmbFavoritesStrings, 0 );
    itemFlexGridSizer3->Add(cmbFavorites, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxRIGHT|wxTOP, 5);

    itemFlexGridSizer3->AddGrowableCol(0);

    wxStaticBox* itemStaticBoxSizer6Static = new wxStaticBox(itemDialog1, wxID_ANY, _("Group Access Rights"));
    wxStaticBoxSizer* itemStaticBoxSizer6 = new wxStaticBoxSizer(itemStaticBoxSizer6Static, wxVERTICAL);
    itemFlexGridSizer2->Add(itemStaticBoxSizer6, 0, wxGROW|wxLEFT|wxRIGHT|wxTOP, 5);

    wxFlexGridSizer* itemFlexGridSizer7 = new wxFlexGridSizer(0, 4, 0, 0);
    itemStaticBoxSizer6->Add(itemFlexGridSizer7, 0, wxGROW, 5);

    wxStaticText* itemStaticText8 = new wxStaticText( itemStaticBoxSizer6->GetStaticBox(), wxID_STATIC, _("Token:"), wxDefaultPosition, wxDefaultSize, 0 );
    itemFlexGridSizer7->Add(itemStaticText8, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 0);

    wxArrayString cmbTokensStrings;
    cmbTokens = new wxChoice( itemStaticBoxSizer6->GetStaticBox(), ID_TOKENLIST, wxDefaultPosition, wxDefaultSize, cmbTokensStrings, 0 );
    itemFlexGridSizer7->Add(cmbTokens, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxALL, 0);

    wxStaticText* itemStaticText10 = new wxStaticText( itemStaticBoxSizer6->GetStaticBox(), wxID_STATIC, _("CryptoGroup:"), wxDefaultPosition, wxDefaultSize, 0 );
    itemFlexGridSizer7->Add(itemStaticText10, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxLEFT, 5);

    wxArrayString cmbCGStrings;
    cmbCG = new wxChoice( itemStaticBoxSizer6->GetStaticBox(), ID_CGLIST, wxDefaultPosition, wxDefaultSize, cmbCGStrings, 0 );
    itemFlexGridSizer7->Add(cmbCG, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxALL, 0);

    itemFlexGridSizer7->AddGrowableCol(1);
    itemFlexGridSizer7->AddGrowableCol(3);

    wxFlexGridSizer* itemFlexGridSizer12 = new wxFlexGridSizer(0, 2, 0, 0);
    itemStaticBoxSizer6->Add(itemFlexGridSizer12, 0, wxGROW|wxALL, 0);

    wxArrayString lstGroupsStrings;
    lstGroups = new wxListBox( itemStaticBoxSizer6->GetStaticBox(), ID_LISTBOX, wxDefaultPosition, wxSize(-1, 215), lstGroupsStrings, wxLB_SINGLE );
    itemFlexGridSizer12->Add(lstGroups, 0, wxGROW|wxALL, 5);

    wxFlexGridSizer* itemFlexGridSizer14 = new wxFlexGridSizer(4, 1, 0, 0);
    itemFlexGridSizer12->Add(itemFlexGridSizer14, 0, wxGROW|wxALL, 5);

    btnAdd = new wxButton( itemStaticBoxSizer6->GetStaticBox(), ID_ADD, _("&Add"), wxDefaultPosition, wxDefaultSize, 0 );
    itemFlexGridSizer14->Add(btnAdd, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 0);

    btnEdit = new wxButton( itemStaticBoxSizer6->GetStaticBox(), ID_EDIT, _("&Edit"), wxDefaultPosition, wxDefaultSize, 0 );
    itemFlexGridSizer14->Add(btnEdit, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 0);

    btnDelete = new wxButton( itemStaticBoxSizer6->GetStaticBox(), ID_DELETE, _("&Delete"), wxDefaultPosition, wxDefaultSize, 0 );
    itemFlexGridSizer14->Add(btnDelete, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 0);

    itemFlexGridSizer14->Add(5, 5, 0, wxALIGN_CENTER_HORIZONTAL|wxGROW|wxALL, 5);

    itemFlexGridSizer14->AddGrowableRow(3);

    itemFlexGridSizer12->AddGrowableRow(0);
    itemFlexGridSizer12->AddGrowableCol(0);

    wxFlexGridSizer* itemFlexGridSizer19 = new wxFlexGridSizer(1, 3, 0, 0);
    itemFlexGridSizer2->Add(itemFlexGridSizer19, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    wxBoxSizer* itemBoxSizer20 = new wxBoxSizer(wxHORIZONTAL);
    itemFlexGridSizer19->Add(itemBoxSizer20, 0, wxALIGN_LEFT|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    btnCreateFavorite = new wxButton( itemDialog1, ID_CREATE_FAVORITE, _("Create &Favorite"), wxDefaultPosition, wxDefaultSize, 0 );
    itemBoxSizer20->Add(btnCreateFavorite, 0, wxALIGN_CENTER_VERTICAL, 5);

    btnDeleteFavorite = new wxButton( itemDialog1, ID_DELETE_FAVORITE, _("Delete Favorite"), wxDefaultPosition, wxDefaultSize, 0 );
    itemBoxSizer20->Add(btnDeleteFavorite, 0, wxALIGN_CENTER_VERTICAL, 5);

    itemFlexGridSizer19->Add(5, 5, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    wxStdDialogButtonSizer* itemStdDialogButtonSizer24 = new wxStdDialogButtonSizer;

    itemFlexGridSizer19->Add(itemStdDialogButtonSizer24, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);
    btnOK = new wxButton( itemDialog1, wxID_OK, _("&OK"), wxDefaultPosition, wxDefaultSize, 0 );
    btnOK->SetDefault();
    itemStdDialogButtonSizer24->AddButton(btnOK);

    btnCancel = new wxButton( itemDialog1, wxID_CANCEL, _("&Cancel"), wxDefaultPosition, wxDefaultSize, 0 );
    itemStdDialogButtonSizer24->AddButton(btnCancel);

    btnHelp = new wxButton( itemDialog1, wxID_HELP, _("&Help"), wxDefaultPosition, wxDefaultSize, 0 );
    itemStdDialogButtonSizer24->AddButton(btnHelp);

    itemStdDialogButtonSizer24->Realize();

    itemFlexGridSizer19->AddGrowableCol(1);

    itemFlexGridSizer2->AddGrowableRow(1);
    itemFlexGridSizer2->AddGrowableCol(0);

////@end AudienceSelector content construction
}


/*
 * Should we show tooltips?
 */

bool AudienceSelector::ShowToolTips()
{
    return true;
}

/*
 * Get bitmap resources
 */

wxBitmap AudienceSelector::GetBitmapResource( const wxString& name )
{
    // Bitmap retrieval
////@begin AudienceSelector bitmap retrieval
    wxUnusedVar(name);
    return wxNullBitmap;
////@end AudienceSelector bitmap retrieval
}

/*
 * Get icon resources
 */

wxIcon AudienceSelector::GetIconResource( const wxString& name )
{
    // Icon retrieval
////@begin AudienceSelector icon retrieval
    wxUnusedVar(name);
    return wxNullIcon;
////@end AudienceSelector icon retrieval
}


/*
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_CLOSE
 */

void AudienceSelector::OnCloseClick( wxCommandEvent& event )
{
////@begin wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_CLOSE in AudienceSelector.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_CLOSE in AudienceSelector. 
}


/*
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_HELP
 */

void AudienceSelector::OnHelpClick( wxCommandEvent& event )
{
////@begin wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_HELP in AudienceSelector.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_HELP in AudienceSelector. 
}


/*
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_DELETE_FAVORITE
 */

void AudienceSelector::OnDeleteFavoriteClick( wxCommandEvent& event )
{
////@begin wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_DELETE_FAVORITE in AudienceSelector.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_DELETE_FAVORITE in AudienceSelector. 
}


/*
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_CREATE_FAVORITE
 */

void AudienceSelector::OnCreateFavoriteClick( wxCommandEvent& event )
{
////@begin wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_CREATE_FAVORITE in AudienceSelector.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_CREATE_FAVORITE in AudienceSelector. 
}


/*
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_DELETE
 */

void AudienceSelector::OnDeleteClick( wxCommandEvent& event )
{
////@begin wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_DELETE in AudienceSelector.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_DELETE in AudienceSelector. 
}


/*
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_EDIT
 */

void AudienceSelector::OnEditClick( wxCommandEvent& event )
{
////@begin wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_EDIT in AudienceSelector.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_EDIT in AudienceSelector. 
}


/*
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_ADD
 */

void AudienceSelector::OnAddClick( wxCommandEvent& event )
{
////@begin wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_ADD in AudienceSelector.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_ADD in AudienceSelector. 
}


/*
 * wxEVT_COMMAND_CHOICE_SELECTED event handler for ID_CGLIST
 */

void AudienceSelector::OnCglistSelected( wxCommandEvent& event )
{
////@begin wxEVT_COMMAND_CHOICE_SELECTED event handler for ID_CGLIST in AudienceSelector.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_COMMAND_CHOICE_SELECTED event handler for ID_CGLIST in AudienceSelector. 
}


/*
 * wxEVT_COMMAND_CHOICE_SELECTED event handler for ID_TOKENLIST
 */

void AudienceSelector::OnTokenlistSelected( wxCommandEvent& event )
{
////@begin wxEVT_COMMAND_CHOICE_SELECTED event handler for ID_TOKENLIST in AudienceSelector.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_COMMAND_CHOICE_SELECTED event handler for ID_TOKENLIST in AudienceSelector. 
}


/*
 * wxEVT_COMMAND_CHOICE_SELECTED event handler for ID_FAVORITELIST
 */

void AudienceSelector::OnFavoritelistSelected( wxCommandEvent& event )
{
////@begin wxEVT_COMMAND_CHOICE_SELECTED event handler for ID_FAVORITELIST in AudienceSelector.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_COMMAND_CHOICE_SELECTED event handler for ID_FAVORITELIST in AudienceSelector. 
}


/*
 * wxEVT_COMMAND_LISTBOX_DOUBLECLICKED event handler for ID_LISTBOX
 */

void AudienceSelector::OnListboxDoubleClicked( wxCommandEvent& event )
{
////@begin wxEVT_COMMAND_LISTBOX_DOUBLECLICKED event handler for ID_LISTBOX in AudienceSelector.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_COMMAND_LISTBOX_DOUBLECLICKED event handler for ID_LISTBOX in AudienceSelector. 
}


/*
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_OK
 */

void AudienceSelector::OnOkClick( wxCommandEvent& event )
{
////@begin wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_OK in AudienceSelector.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_OK in AudienceSelector. 
}


/*
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_CANCEL
 */

void AudienceSelector::OnCancelClick( wxCommandEvent& event )
{
////@begin wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_CANCEL in AudienceSelector.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_CANCEL in AudienceSelector. 
}


/*
 * wxEVT_COMMAND_LISTBOX_SELECTED event handler for ID_LISTBOX
 */

void AudienceSelector::OnListboxSelected( wxCommandEvent& event )
{
////@begin wxEVT_COMMAND_LISTBOX_SELECTED event handler for ID_LISTBOX in AudienceSelector.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_COMMAND_LISTBOX_SELECTED event handler for ID_LISTBOX in AudienceSelector. 
}

