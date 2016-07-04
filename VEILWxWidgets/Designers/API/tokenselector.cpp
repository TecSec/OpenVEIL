/////////////////////////////////////////////////////////////////////////////
// Name:        tokenselector.cpp
// Purpose:     
// Author:      Roger Butler
// Modified by: 
// Created:     09/02/2016 17:56:57
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
#include "wx/imaglist.h"
////@end includes

#include "tokenselector.h"

////@begin XPM images
////@end XPM images


/*
 * TokenSelector type definition
 */

IMPLEMENT_DYNAMIC_CLASS( TokenSelector, wxDialog )


/*
 * TokenSelector event table definition
 */

BEGIN_EVENT_TABLE( TokenSelector, wxDialog )

////@begin TokenSelector event table entries
    EVT_LIST_ITEM_SELECTED( ID_TOKENS, TokenSelector::OnTokensSelected )
    EVT_LIST_ITEM_DESELECTED( ID_TOKENS, TokenSelector::OnTokensDeselected )
    EVT_LIST_ITEM_ACTIVATED( ID_TOKENS, TokenSelector::OnTokensItemActivated )
    EVT_BUTTON( wxID_OK, TokenSelector::OnOkClick )
    EVT_BUTTON( wxID_CANCEL, TokenSelector::OnCancelClick )
    EVT_BUTTON( wxID_APPLY, TokenSelector::OnApplyClick )
    EVT_BUTTON( wxID_HELP, TokenSelector::OnHelpClick )
////@end TokenSelector event table entries

END_EVENT_TABLE()


/*
 * TokenSelector constructors
 */

TokenSelector::TokenSelector()
{
    Init();
}

TokenSelector::TokenSelector( wxWindow* parent, wxWindowID id, const wxString& caption, const wxPoint& pos, const wxSize& size, long style )
{
    Init();
    Create(parent, id, caption, pos, size, style);
}


/*
 * TokenSelector creator
 */

bool TokenSelector::Create( wxWindow* parent, wxWindowID id, const wxString& caption, const wxPoint& pos, const wxSize& size, long style )
{
////@begin TokenSelector creation
    SetExtraStyle(wxWS_EX_VALIDATE_RECURSIVELY|wxWS_EX_BLOCK_EVENTS);
    wxDialog::Create( parent, id, caption, pos, size, style );

    CreateControls();
    if (GetSizer())
    {
        GetSizer()->SetSizeHints(this);
    }
    Centre();
////@end TokenSelector creation
    return true;
}


/*
 * TokenSelector destructor
 */

TokenSelector::~TokenSelector()
{
////@begin TokenSelector destruction
////@end TokenSelector destruction
}


/*
 * Member initialisation
 */

void TokenSelector::Init()
{
////@begin TokenSelector member initialisation
    lblExplanation = NULL;
    lstTokens = NULL;
    btnRefresh = NULL;
////@end TokenSelector member initialisation
}


/*
 * Control creation for TokenSelector
 */

void TokenSelector::CreateControls()
{    
////@begin TokenSelector content construction
    TokenSelector* itemDialog1 = this;

    wxFlexGridSizer* itemFlexGridSizer2 = new wxFlexGridSizer(0, 1, 0, 0);
    itemDialog1->SetSizer(itemFlexGridSizer2);

    lblExplanation = new wxStaticText( itemDialog1, ID_EXPLANATION, _("Select a Token.  Click Refresh to update the list after Tokens are added or changed."), wxDefaultPosition, wxDefaultSize, 0 );
    itemFlexGridSizer2->Add(lblExplanation, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    lstTokens = new wxListCtrl( itemDialog1, ID_TOKENS, wxDefaultPosition, wxSize(100, 200), wxLC_REPORT|wxLC_SINGLE_SEL );
    itemFlexGridSizer2->Add(lstTokens, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    wxStdDialogButtonSizer* itemStdDialogButtonSizer5 = new wxStdDialogButtonSizer;

    itemFlexGridSizer2->Add(itemStdDialogButtonSizer5, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);
    wxButton* itemButton6 = new wxButton( itemDialog1, wxID_OK, _("&OK"), wxDefaultPosition, wxDefaultSize, 0 );
    itemButton6->SetName(wxT("btnOK"));
    itemStdDialogButtonSizer5->AddButton(itemButton6);

    wxButton* itemButton7 = new wxButton( itemDialog1, wxID_CANCEL, _("&Cancel"), wxDefaultPosition, wxDefaultSize, 0 );
    itemButton7->SetName(wxT("btnCancel"));
    itemStdDialogButtonSizer5->AddButton(itemButton7);

    btnRefresh = new wxButton( itemDialog1, wxID_APPLY, _("&Refresh"), wxDefaultPosition, wxDefaultSize, 0 );
    itemStdDialogButtonSizer5->AddButton(btnRefresh);

    wxButton* itemButton9 = new wxButton( itemDialog1, wxID_HELP, _("&Help"), wxDefaultPosition, wxDefaultSize, 0 );
    itemStdDialogButtonSizer5->AddButton(itemButton9);

    itemStdDialogButtonSizer5->Realize();

////@end TokenSelector content construction
}


/*
 * Should we show tooltips?
 */

bool TokenSelector::ShowToolTips()
{
    return true;
}

/*
 * Get bitmap resources
 */

wxBitmap TokenSelector::GetBitmapResource( const wxString& name )
{
    // Bitmap retrieval
////@begin TokenSelector bitmap retrieval
    wxUnusedVar(name);
    return wxNullBitmap;
////@end TokenSelector bitmap retrieval
}

/*
 * Get icon resources
 */

wxIcon TokenSelector::GetIconResource( const wxString& name )
{
    // Icon retrieval
////@begin TokenSelector icon retrieval
    wxUnusedVar(name);
    return wxNullIcon;
////@end TokenSelector icon retrieval
}


/*
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_APPLY
 */

void TokenSelector::OnApplyClick( wxCommandEvent& event )
{
////@begin wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_APPLY in TokenSelector.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_APPLY in TokenSelector. 
}


/*
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_CANCEL
 */

void TokenSelector::OnCancelClick( wxCommandEvent& event )
{
////@begin wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_CANCEL in TokenSelector.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_CANCEL in TokenSelector. 
}


/*
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_OK
 */

void TokenSelector::OnOkClick( wxCommandEvent& event )
{
////@begin wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_OK in TokenSelector.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_OK in TokenSelector. 
}


/*
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_HELP
 */

void TokenSelector::OnHelpClick( wxCommandEvent& event )
{
////@begin wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_HELP in TokenSelector.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_HELP in TokenSelector. 
}


/*
 * wxEVT_COMMAND_LIST_ITEM_SELECTED event handler for ID_TOKENS
 */

void TokenSelector::OnTokensSelected( wxListEvent& event )
{
////@begin wxEVT_COMMAND_LIST_ITEM_SELECTED event handler for ID_TOKENS in TokenSelector.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_COMMAND_LIST_ITEM_SELECTED event handler for ID_TOKENS in TokenSelector. 
}


/*
 * wxEVT_COMMAND_LIST_ITEM_DESELECTED event handler for ID_TOKENS
 */

void TokenSelector::OnTokensDeselected( wxListEvent& event )
{
////@begin wxEVT_COMMAND_LIST_ITEM_DESELECTED event handler for ID_TOKENS in TokenSelector.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_COMMAND_LIST_ITEM_DESELECTED event handler for ID_TOKENS in TokenSelector. 
}


/*
 * wxEVT_COMMAND_LIST_ITEM_ACTIVATED event handler for ID_TOKENS
 */

void TokenSelector::OnTokensItemActivated( wxListEvent& event )
{
////@begin wxEVT_COMMAND_LIST_ITEM_ACTIVATED event handler for ID_TOKENS in TokenSelector.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_COMMAND_LIST_ITEM_ACTIVATED event handler for ID_TOKENS in TokenSelector. 
}

