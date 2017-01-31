/////////////////////////////////////////////////////////////////////////////
// Name:        keyveillogin.cpp
// Purpose:     
// Author:      Roger Butler
// Modified by: 
// Created:     09/02/2016 11:56:54
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

#include "keyveillogin.h"

////@begin XPM images
#include "../../src/tecseclogo.xpm"
////@end XPM images


/*
 * KeyVEILLogin type definition
 */

IMPLEMENT_DYNAMIC_CLASS( KeyVEILLogin, wxDialog )


/*
 * KeyVEILLogin event table definition
 */

BEGIN_EVENT_TABLE( KeyVEILLogin, wxDialog )

////@begin KeyVEILLogin event table entries
    EVT_BUTTON( wxID_HELP, KeyVEILLogin::OnHelpClick )
    EVT_BUTTON( wxID_OK, KeyVEILLogin::OnOkClick )
    EVT_BUTTON( wxID_APPLY, KeyVEILLogin::OnApplyClick )
////@end KeyVEILLogin event table entries

END_EVENT_TABLE()


/*
 * KeyVEILLogin constructors
 */

KeyVEILLogin::KeyVEILLogin()
{
    Init();
}

KeyVEILLogin::KeyVEILLogin( wxWindow* parent, wxWindowID id, const wxString& caption, const wxPoint& pos, const wxSize& size, long style )
{
    Init();
    Create(parent, id, caption, pos, size, style);
}


/*
 * KeyVEILLogin creator
 */

bool KeyVEILLogin::Create( wxWindow* parent, wxWindowID id, const wxString& caption, const wxPoint& pos, const wxSize& size, long style )
{
////@begin KeyVEILLogin creation
    SetExtraStyle(wxWS_EX_VALIDATE_RECURSIVELY|wxWS_EX_BLOCK_EVENTS);
    wxDialog::Create( parent, id, caption, pos, size, style );

    CreateControls();
    if (GetSizer())
    {
        GetSizer()->SetSizeHints(this);
    }
    Centre();
////@end KeyVEILLogin creation
    return true;
}


/*
 * KeyVEILLogin destructor
 */

KeyVEILLogin::~KeyVEILLogin()
{
////@begin KeyVEILLogin destruction
////@end KeyVEILLogin destruction
}


/*
 * Member initialisation
 */

void KeyVEILLogin::Init()
{
////@begin KeyVEILLogin member initialisation
    edtURL = NULL;
    edtUsername = NULL;
    edtPassword = NULL;
    edtStatus = NULL;
////@end KeyVEILLogin member initialisation
}


/*
 * Control creation for KeyVEILLogin
 */

void KeyVEILLogin::CreateControls()
{    
////@begin KeyVEILLogin content construction
    KeyVEILLogin* itemDialog1 = this;

    wxFlexGridSizer* itemFlexGridSizer2 = new wxFlexGridSizer(6, 1, 0, 0);
    itemDialog1->SetSizer(itemFlexGridSizer2);

    wxStaticBitmap* itemStaticBitmap3 = new wxStaticBitmap( itemDialog1, wxID_STATIC, itemDialog1->GetBitmapResource(wxT("../../src/tecseclogo.xpm")), wxDefaultPosition, wxSize(372, 73), 0 );
    itemFlexGridSizer2->Add(itemStaticBitmap3, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 0);

    wxFlexGridSizer* itemFlexGridSizer4 = new wxFlexGridSizer(0, 2, 0, 0);
    itemFlexGridSizer2->Add(itemFlexGridSizer4, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    wxStaticText* itemStaticText5 = new wxStaticText( itemDialog1, wxID_STATIC, _("KeyVEIL URL:"), wxDefaultPosition, wxDefaultSize, 0 );
    itemFlexGridSizer4->Add(itemStaticText5, 0, wxALIGN_LEFT|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    edtURL = new wxTextCtrl( itemDialog1, ID_URL, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
    itemFlexGridSizer4->Add(edtURL, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxALL, 0);

    wxStaticText* itemStaticText7 = new wxStaticText( itemDialog1, wxID_STATIC, _("Username:"), wxDefaultPosition, wxDefaultSize, 0 );
    itemFlexGridSizer4->Add(itemStaticText7, 0, wxALIGN_LEFT|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    edtUsername = new wxTextCtrl( itemDialog1, ID_USERNAME, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
    itemFlexGridSizer4->Add(edtUsername, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxALL, 0);

    itemFlexGridSizer4->AddGrowableCol(1);

    wxStaticText* itemStaticText9 = new wxStaticText( itemDialog1, wxID_STATIC, _("Please enter the user password here:"), wxDefaultPosition, wxDefaultSize, 0 );
    itemFlexGridSizer2->Add(itemStaticText9, 0, wxALIGN_LEFT|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    edtPassword = new wxTextCtrl( itemDialog1, ID_PASSWORD, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_PASSWORD );
    edtPassword->SetMaxLength(64);
    itemFlexGridSizer2->Add(edtPassword, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    edtStatus = new wxStaticText( itemDialog1, ID_STATUS, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
    edtStatus->Wrap(360);
    itemFlexGridSizer2->Add(edtStatus, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    wxStdDialogButtonSizer* itemStdDialogButtonSizer12 = new wxStdDialogButtonSizer;

    itemFlexGridSizer2->Add(itemStdDialogButtonSizer12, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);
    wxButton* itemButton13 = new wxButton( itemDialog1, wxID_CANCEL, _("&Cancel"), wxDefaultPosition, wxDefaultSize, 0 );
    itemStdDialogButtonSizer12->AddButton(itemButton13);

    wxButton* itemButton14 = new wxButton( itemDialog1, wxID_HELP, _("&Help"), wxDefaultPosition, wxDefaultSize, 0 );
    itemStdDialogButtonSizer12->AddButton(itemButton14);

    wxButton* itemButton15 = new wxButton( itemDialog1, wxID_OK, _("&OK"), wxDefaultPosition, wxDefaultSize, 0 );
    itemButton15->SetDefault();
    itemStdDialogButtonSizer12->AddButton(itemButton15);

    wxButton* itemButton16 = new wxButton( itemDialog1, wxID_APPLY, _("&About"), wxDefaultPosition, wxDefaultSize, 0 );
    itemStdDialogButtonSizer12->AddButton(itemButton16);

    itemStdDialogButtonSizer12->Realize();

    itemFlexGridSizer2->AddGrowableRow(5);

////@end KeyVEILLogin content construction
}


/*
 * Should we show tooltips?
 */

bool KeyVEILLogin::ShowToolTips()
{
    return true;
}

/*
 * Get bitmap resources
 */

wxBitmap KeyVEILLogin::GetBitmapResource( const wxString& name )
{
    // Bitmap retrieval
////@begin KeyVEILLogin bitmap retrieval
    wxUnusedVar(name);
    if (name == wxT("../../src/tecseclogo.xpm"))
    {
        wxBitmap bitmap(tecseclogo_xpm);
        return bitmap;
    }
    return wxNullBitmap;
////@end KeyVEILLogin bitmap retrieval
}

/*
 * Get icon resources
 */

wxIcon KeyVEILLogin::GetIconResource( const wxString& name )
{
    // Icon retrieval
////@begin KeyVEILLogin icon retrieval
    wxUnusedVar(name);
    return wxNullIcon;
////@end KeyVEILLogin icon retrieval
}


/*
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_APPLY
 */

void KeyVEILLogin::OnApplyClick( wxCommandEvent& event )
{
////@begin wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_APPLY in KeyVEILLogin.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_APPLY in KeyVEILLogin. 
}


/*
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_HELP
 */

void KeyVEILLogin::OnHelpClick( wxCommandEvent& event )
{
////@begin wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_HELP in KeyVEILLogin.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_HELP in KeyVEILLogin. 
}


/*
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_OK
 */

void KeyVEILLogin::OnOkClick( wxCommandEvent& event )
{
////@begin wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_OK in KeyVEILLogin.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_OK in KeyVEILLogin. 
}

