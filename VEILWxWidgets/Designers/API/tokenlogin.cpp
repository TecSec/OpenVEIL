/////////////////////////////////////////////////////////////////////////////
// Name:        tokenlogin.cpp
// Purpose:     
// Author:      Roger Butler
// Modified by: 
// Created:     09/02/2016 17:15:39
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

#include "tokenlogin.h"

////@begin XPM images
#include "../../src/tecseclogo.xpm"
////@end XPM images


/*
 * TokenLogin type definition
 */

IMPLEMENT_DYNAMIC_CLASS( TokenLogin, wxDialog )


/*
 * TokenLogin event table definition
 */

BEGIN_EVENT_TABLE( TokenLogin, wxDialog )

////@begin TokenLogin event table entries
    EVT_BUTTON( wxID_OK, TokenLogin::OnOkClick )
    EVT_BUTTON( wxID_CANCEL, TokenLogin::OnCancelClick )
    EVT_BUTTON( wxID_APPLY, TokenLogin::OnApplyClick )
////@end TokenLogin event table entries

END_EVENT_TABLE()


/*
 * TokenLogin constructors
 */

TokenLogin::TokenLogin()
{
    Init();
}

TokenLogin::TokenLogin( wxWindow* parent, wxWindowID id, const wxString& caption, const wxPoint& pos, const wxSize& size, long style )
{
    Init();
    Create(parent, id, caption, pos, size, style);
}


/*
 * TokenLogin creator
 */

bool TokenLogin::Create( wxWindow* parent, wxWindowID id, const wxString& caption, const wxPoint& pos, const wxSize& size, long style )
{
////@begin TokenLogin creation
    SetExtraStyle(wxWS_EX_VALIDATE_RECURSIVELY|wxWS_EX_BLOCK_EVENTS);
    wxDialog::Create( parent, id, caption, pos, size, style );

    CreateControls();
    if (GetSizer())
    {
        GetSizer()->SetSizeHints(this);
    }
    Centre();
////@end TokenLogin creation
    return true;
}


/*
 * TokenLogin destructor
 */

TokenLogin::~TokenLogin()
{
////@begin TokenLogin destruction
////@end TokenLogin destruction
}


/*
 * Member initialisation
 */

void TokenLogin::Init()
{
////@begin TokenLogin member initialisation
    lblTokenName = NULL;
    edtPassword = NULL;
    lblStatus = NULL;
    btnOK = NULL;
    btnCancel = NULL;
    btnAbout = NULL;
////@end TokenLogin member initialisation
}


/*
 * Control creation for TokenLogin
 */

void TokenLogin::CreateControls()
{    
////@begin TokenLogin content construction
    TokenLogin* itemDialog1 = this;

    wxFlexGridSizer* itemFlexGridSizer2 = new wxFlexGridSizer(0, 1, 0, 0);
    itemDialog1->SetSizer(itemFlexGridSizer2);

    wxStaticBitmap* itemStaticBitmap3 = new wxStaticBitmap( itemDialog1, wxID_STATIC, itemDialog1->GetBitmapResource(wxT("../../src/tecseclogo.xpm")), wxDefaultPosition, wxSize(372, 73), 0 );
    itemFlexGridSizer2->Add(itemStaticBitmap3, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 0);

    wxFlexGridSizer* itemFlexGridSizer4 = new wxFlexGridSizer(0, 2, 0, 0);
    itemFlexGridSizer2->Add(itemFlexGridSizer4, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    wxStaticText* itemStaticText5 = new wxStaticText( itemDialog1, wxID_STATIC, _("Token Name:"), wxDefaultPosition, wxDefaultSize, 0 );
    itemFlexGridSizer4->Add(itemStaticText5, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    lblTokenName = new wxStaticText( itemDialog1, ID_TOKENNAME, _("Static text"), wxDefaultPosition, wxDefaultSize, 0 );
    lblTokenName->Wrap(300);
    itemFlexGridSizer4->Add(lblTokenName, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    itemFlexGridSizer2->Add(5, 5, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    wxStaticText* itemStaticText8 = new wxStaticText( itemDialog1, wxID_STATIC, _("Please enter the token password here:"), wxDefaultPosition, wxDefaultSize, 0 );
    itemFlexGridSizer2->Add(itemStaticText8, 0, wxALIGN_LEFT|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    edtPassword = new wxTextCtrl( itemDialog1, ID_TEXTCTRL, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_PASSWORD );
    itemFlexGridSizer2->Add(edtPassword, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    lblStatus = new wxStaticText( itemDialog1, ID_STATUS, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
    lblStatus->Wrap(360);
    itemFlexGridSizer2->Add(lblStatus, 0, wxALIGN_LEFT|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    wxStdDialogButtonSizer* itemStdDialogButtonSizer11 = new wxStdDialogButtonSizer;

    itemFlexGridSizer2->Add(itemStdDialogButtonSizer11, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);
    btnOK = new wxButton( itemDialog1, wxID_OK, _("&OK"), wxDefaultPosition, wxDefaultSize, 0 );
    btnOK->SetDefault();
    itemStdDialogButtonSizer11->AddButton(btnOK);

    btnCancel = new wxButton( itemDialog1, wxID_CANCEL, _("&Cancel"), wxDefaultPosition, wxDefaultSize, 0 );
    itemStdDialogButtonSizer11->AddButton(btnCancel);

    btnAbout = new wxButton( itemDialog1, wxID_APPLY, _("&About"), wxDefaultPosition, wxDefaultSize, 0 );
    itemStdDialogButtonSizer11->AddButton(btnAbout);

    itemStdDialogButtonSizer11->Realize();

////@end TokenLogin content construction
}


/*
 * Should we show tooltips?
 */

bool TokenLogin::ShowToolTips()
{
    return true;
}

/*
 * Get bitmap resources
 */

wxBitmap TokenLogin::GetBitmapResource( const wxString& name )
{
    // Bitmap retrieval
////@begin TokenLogin bitmap retrieval
    wxUnusedVar(name);
    if (name == wxT("../../src/tecseclogo.xpm"))
    {
        wxBitmap bitmap(tecseclogo_xpm);
        return bitmap;
    }
    return wxNullBitmap;
////@end TokenLogin bitmap retrieval
}

/*
 * Get icon resources
 */

wxIcon TokenLogin::GetIconResource( const wxString& name )
{
    // Icon retrieval
////@begin TokenLogin icon retrieval
    wxUnusedVar(name);
    return wxNullIcon;
////@end TokenLogin icon retrieval
}


/*
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_OK
 */

void TokenLogin::OnOkClick( wxCommandEvent& event )
{
////@begin wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_OK in TokenLogin.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_OK in TokenLogin. 
}


/*
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_CANCEL
 */

void TokenLogin::OnCancelClick( wxCommandEvent& event )
{
////@begin wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_CANCEL in TokenLogin.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_CANCEL in TokenLogin. 
}


/*
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_APPLY
 */

void TokenLogin::OnApplyClick( wxCommandEvent& event )
{
////@begin wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_APPLY in TokenLogin.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_APPLY in TokenLogin. 
}

