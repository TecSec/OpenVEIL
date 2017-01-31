/////////////////////////////////////////////////////////////////////////////
// Name:        generalsettingshandler.cpp
// Purpose:     
// Author:      Roger Butler
// Modified by: 
// Created:     10/02/2016 14:45:17
// RCS-ID:      
// Copyright:   Copyright (c) 2017, TecSec, Inc.  
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

#include "generalsettingshandler.h"

////@begin XPM images
////@end XPM images


/*
 * GeneralSettingsHandler type definition
 */

IMPLEMENT_DYNAMIC_CLASS( GeneralSettingsHandler, wxPanel )


/*
 * GeneralSettingsHandler event table definition
 */

BEGIN_EVENT_TABLE( GeneralSettingsHandler, wxPanel )

////@begin GeneralSettingsHandler event table entries
    EVT_TEXT( ID_URL, GeneralSettingsHandler::OnUrlTextUpdated )
    EVT_TEXT( ID_USERNAME, GeneralSettingsHandler::OnUsernameTextUpdated )
    EVT_CHOICE( ID_ENCRYPTION, GeneralSettingsHandler::OnEncryptionSelected )
    EVT_CHOICE( ID_HASH, GeneralSettingsHandler::OnHashSelected )
    EVT_TEXT( ID_TEXTCTRL, GeneralSettingsHandler::OnTextctrlTextUpdated )
////@end GeneralSettingsHandler event table entries

END_EVENT_TABLE()


/*
 * GeneralSettingsHandler constructors
 */

GeneralSettingsHandler::GeneralSettingsHandler()
{
    Init();
}

GeneralSettingsHandler::GeneralSettingsHandler( wxWindow* parent, wxWindowID id, const wxString& caption, const wxPoint& pos, const wxSize& size, long style )
{
    Init();
    Create(parent, id, caption, pos, size, style);
}


/*
 * GeneralSettingsHandler creator
 */

bool GeneralSettingsHandler::Create( wxWindow* parent, wxWindowID id, const wxString& caption, const wxPoint& pos, const wxSize& size, long style )
{
////@begin GeneralSettingsHandler creation
    SetExtraStyle(wxWS_EX_VALIDATE_RECURSIVELY|wxWS_EX_BLOCK_EVENTS);
    wxPanel::Create( parent, id, pos, size, style );

    CreateControls();
    Centre();
////@end GeneralSettingsHandler creation
    return true;
}


/*
 * GeneralSettingsHandler destructor
 */

GeneralSettingsHandler::~GeneralSettingsHandler()
{
////@begin GeneralSettingsHandler destruction
////@end GeneralSettingsHandler destruction
}


/*
 * Member initialisation
 */

void GeneralSettingsHandler::Init()
{
////@begin GeneralSettingsHandler member initialisation
    edtKeyVEILUrl = NULL;
    edtKeyVEILUsername = NULL;
    cmbEncryption = NULL;
    cmbHash = NULL;
////@end GeneralSettingsHandler member initialisation
}


/*
 * Control creation for GeneralSettingsHandler
 */

void GeneralSettingsHandler::CreateControls()
{    
////@begin GeneralSettingsHandler content construction
    GeneralSettingsHandler* itemPanel1 = this;

    wxFlexGridSizer* itemFlexGridSizer2 = new wxFlexGridSizer(0, 1, 0, 0);
    itemPanel1->SetSizer(itemFlexGridSizer2);

    wxStaticText* itemStaticText3 = new wxStaticText( itemPanel1, wxID_STATIC, _("KeyVEIL URL:"), wxDefaultPosition, wxDefaultSize, 0 );
    itemFlexGridSizer2->Add(itemStaticText3, 0, wxALIGN_LEFT|wxALIGN_CENTER_VERTICAL|wxLEFT|wxRIGHT|wxTOP, 5);

    edtKeyVEILUrl = new wxTextCtrl( itemPanel1, ID_URL, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
    edtKeyVEILUrl->SetMaxLength(200);
    itemFlexGridSizer2->Add(edtKeyVEILUrl, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    wxStaticText* itemStaticText5 = new wxStaticText( itemPanel1, wxID_STATIC, _("Default KeyVEIL user name:"), wxDefaultPosition, wxDefaultSize, 0 );
    itemFlexGridSizer2->Add(itemStaticText5, 0, wxALIGN_LEFT|wxALIGN_CENTER_VERTICAL|wxLEFT|wxRIGHT|wxTOP, 5);

    edtKeyVEILUsername = new wxTextCtrl( itemPanel1, ID_USERNAME, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
    edtKeyVEILUsername->SetMaxLength(50);
    itemFlexGridSizer2->Add(edtKeyVEILUsername, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    wxStaticText* itemStaticText7 = new wxStaticText( itemPanel1, wxID_STATIC, _("&Default Encryption Algorithm"), wxDefaultPosition, wxDefaultSize, 0 );
    itemFlexGridSizer2->Add(itemStaticText7, 0, wxALIGN_LEFT|wxALIGN_CENTER_VERTICAL|wxLEFT|wxRIGHT|wxTOP, 5);

    wxFlexGridSizer* itemFlexGridSizer8 = new wxFlexGridSizer(0, 2, 0, 0);
    itemFlexGridSizer2->Add(itemFlexGridSizer8, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxLEFT|wxRIGHT|wxBOTTOM, 5);

    wxArrayString cmbEncryptionStrings;
    cmbEncryption = new wxChoice( itemPanel1, ID_ENCRYPTION, wxDefaultPosition, wxDefaultSize, cmbEncryptionStrings, 0 );
    itemFlexGridSizer8->Add(cmbEncryption, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxRIGHT|wxTOP, 5);

    wxStaticText* itemStaticText10 = new wxStaticText( itemPanel1, wxID_STATIC, _("This algorithm is used by VEIL applications for data security."), wxDefaultPosition, wxDefaultSize, 0 );
    itemStaticText10->Wrap(300);
    itemFlexGridSizer8->Add(itemStaticText10, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxLEFT|wxRIGHT|wxTOP, 5);

    itemFlexGridSizer8->AddGrowableCol(0);

    wxStaticText* itemStaticText11 = new wxStaticText( itemPanel1, wxID_STATIC, _("Default Hash Algorithm:"), wxDefaultPosition, wxDefaultSize, 0 );
    itemFlexGridSizer2->Add(itemStaticText11, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxLEFT|wxRIGHT|wxTOP, 5);

    wxFlexGridSizer* itemFlexGridSizer12 = new wxFlexGridSizer(0, 2, 0, 0);
    itemFlexGridSizer2->Add(itemFlexGridSizer12, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxLEFT|wxRIGHT|wxBOTTOM, 5);

    wxArrayString cmbHashStrings;
    cmbHash = new wxChoice( itemPanel1, ID_HASH, wxDefaultPosition, wxDefaultSize, cmbHashStrings, 0 );
    itemFlexGridSizer12->Add(cmbHash, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxRIGHT|wxTOP, 5);

    wxStaticText* itemStaticText14 = new wxStaticText( itemPanel1, wxID_STATIC, _("This algorithm is used by VEIL applications for data integrity."), wxDefaultPosition, wxDefaultSize, 0 );
    itemStaticText14->Wrap(300);
    itemFlexGridSizer12->Add(itemStaticText14, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxLEFT|wxRIGHT|wxTOP, 5);

    itemFlexGridSizer12->AddGrowableCol(0);

    wxStaticText* itemStaticText15 = new wxStaticText( itemPanel1, wxID_STATIC, _("Enter the smart card identifiers (AIDs) that are to be supported:"), wxDefaultPosition, wxDefaultSize, 0 );
    itemFlexGridSizer2->Add(itemStaticText15, 0, wxALIGN_LEFT|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    wxTextCtrl* itemTextCtrl16 = new wxTextCtrl( itemPanel1, ID_TEXTCTRL, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
    itemTextCtrl16->SetMaxLength(500);
    itemTextCtrl16->SetName(wxT("edtAIDList"));
    itemFlexGridSizer2->Add(itemTextCtrl16, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    itemFlexGridSizer2->AddGrowableCol(0);

////@end GeneralSettingsHandler content construction
}


/*
 * Should we show tooltips?
 */

bool GeneralSettingsHandler::ShowToolTips()
{
    return true;
}

/*
 * Get bitmap resources
 */

wxBitmap GeneralSettingsHandler::GetBitmapResource( const wxString& name )
{
    // Bitmap retrieval
////@begin GeneralSettingsHandler bitmap retrieval
    wxUnusedVar(name);
    return wxNullBitmap;
////@end GeneralSettingsHandler bitmap retrieval
}

/*
 * Get icon resources
 */

wxIcon GeneralSettingsHandler::GetIconResource( const wxString& name )
{
    // Icon retrieval
////@begin GeneralSettingsHandler icon retrieval
    wxUnusedVar(name);
    return wxNullIcon;
////@end GeneralSettingsHandler icon retrieval
}


/*
 * wxEVT_COMMAND_CHOICE_SELECTED event handler for ID_ENCRYPTION
 */

void GeneralSettingsHandler::OnEncryptionSelected( wxCommandEvent& event )
{
////@begin wxEVT_COMMAND_CHOICE_SELECTED event handler for ID_ENCRYPTION in GeneralSettingsHandler.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_COMMAND_CHOICE_SELECTED event handler for ID_ENCRYPTION in GeneralSettingsHandler. 
}


/*
 * wxEVT_COMMAND_CHOICE_SELECTED event handler for ID_HASH
 */

void GeneralSettingsHandler::OnHashSelected( wxCommandEvent& event )
{
////@begin wxEVT_COMMAND_CHOICE_SELECTED event handler for ID_HASH in GeneralSettingsHandler.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_COMMAND_CHOICE_SELECTED event handler for ID_HASH in GeneralSettingsHandler. 
}


/*
 * wxEVT_COMMAND_TEXT_UPDATED event handler for ID_URL
 */

void GeneralSettingsHandler::OnUrlTextUpdated( wxCommandEvent& event )
{
////@begin wxEVT_COMMAND_TEXT_UPDATED event handler for ID_URL in GeneralSettingsHandler.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_COMMAND_TEXT_UPDATED event handler for ID_URL in GeneralSettingsHandler. 
}


/*
 * wxEVT_COMMAND_TEXT_UPDATED event handler for ID_USERNAME
 */

void GeneralSettingsHandler::OnUsernameTextUpdated( wxCommandEvent& event )
{
////@begin wxEVT_COMMAND_TEXT_UPDATED event handler for ID_USERNAME in GeneralSettingsHandler.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_COMMAND_TEXT_UPDATED event handler for ID_USERNAME in GeneralSettingsHandler. 
}


/*
 * wxEVT_COMMAND_TEXT_UPDATED event handler for ID_TEXTCTRL
 */

void GeneralSettingsHandler::OnTextctrlTextUpdated( wxCommandEvent& event )
{
////@begin wxEVT_COMMAND_TEXT_UPDATED event handler for ID_TEXTCTRL in GeneralSettingsHandler.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_COMMAND_TEXT_UPDATED event handler for ID_TEXTCTRL in GeneralSettingsHandler. 
}

