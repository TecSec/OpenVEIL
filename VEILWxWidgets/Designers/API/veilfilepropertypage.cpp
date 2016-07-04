/////////////////////////////////////////////////////////////////////////////
// Name:        veilfilepropertypage.cpp
// Purpose:     
// Author:      Roger Butler
// Modified by: 
// Created:     10/02/2016 15:13:35
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

#include "veilfilepropertypage.h"

////@begin XPM images
////@end XPM images


/*
 * VEILFilePropertyPage type definition
 */

IMPLEMENT_DYNAMIC_CLASS( VEILFilePropertyPage, wxPanel )


/*
 * VEILFilePropertyPage event table definition
 */

BEGIN_EVENT_TABLE( VEILFilePropertyPage, wxPanel )

////@begin VEILFilePropertyPage event table entries
    EVT_CHECKBOX( ID_OVERWRITE_EXISTING, VEILFilePropertyPage::OnOverwriteExistingClick )
    EVT_CHECKBOX( ID_CLOSE_WHEN_DONE, VEILFilePropertyPage::OnCloseWhenDoneClick )
    EVT_CHECKBOX( ID_DELETE_ENCRYPTION, VEILFilePropertyPage::OnDeleteEncryptionClick )
    EVT_CHECKBOX( ID_DELETE_ON_DECRYPTION, VEILFilePropertyPage::OnDeleteOnDecryptionClick )
    EVT_TEXT( ID_TIMEOUT, VEILFilePropertyPage::OnTimeoutTextUpdated )
    EVT_TEXT( ID_PASSES, VEILFilePropertyPage::OnPassesTextUpdated )
    EVT_CHECKBOX( ID_ON_TOP, VEILFilePropertyPage::OnOnTopClick )
    EVT_CHOICE( ID_COMPRESSION, VEILFilePropertyPage::OnCompressionSelected )
////@end VEILFilePropertyPage event table entries

END_EVENT_TABLE()


/*
 * VEILFilePropertyPage constructors
 */

VEILFilePropertyPage::VEILFilePropertyPage()
{
    Init();
}

VEILFilePropertyPage::VEILFilePropertyPage( wxWindow* parent, wxWindowID id, const wxString& caption, const wxPoint& pos, const wxSize& size, long style )
{
    Init();
    Create(parent, id, caption, pos, size, style);
}


/*
 * VEILFilePropertyPage creator
 */

bool VEILFilePropertyPage::Create( wxWindow* parent, wxWindowID id, const wxString& caption, const wxPoint& pos, const wxSize& size, long style )
{
////@begin VEILFilePropertyPage creation
    SetExtraStyle(wxWS_EX_VALIDATE_RECURSIVELY|wxWS_EX_BLOCK_EVENTS);
    wxPanel::Create( parent, id, pos, size, style );

    CreateControls();
    Centre();
////@end VEILFilePropertyPage creation
    return true;
}


/*
 * VEILFilePropertyPage destructor
 */

VEILFilePropertyPage::~VEILFilePropertyPage()
{
////@begin VEILFilePropertyPage destruction
////@end VEILFilePropertyPage destruction
}


/*
 * Member initialisation
 */

void VEILFilePropertyPage::Init()
{
////@begin VEILFilePropertyPage member initialisation
    chkOverwriteExisting = NULL;
    chkCloseWhenDone = NULL;
    chkDeleteAfterEncryption = NULL;
    chkDeleteAfterDecryption = NULL;
    edtTimeout = NULL;
    edtPasses = NULL;
    chkOnTop = NULL;
    cmbCompression = NULL;
////@end VEILFilePropertyPage member initialisation
}


/*
 * Control creation for VEILFilePropertyPage
 */

void VEILFilePropertyPage::CreateControls()
{    
////@begin VEILFilePropertyPage content construction
    VEILFilePropertyPage* itemPanel1 = this;

    wxFlexGridSizer* itemFlexGridSizer2 = new wxFlexGridSizer(0, 1, 0, 0);
    itemPanel1->SetSizer(itemFlexGridSizer2);

    wxFlexGridSizer* itemFlexGridSizer3 = new wxFlexGridSizer(0, 2, 0, 0);
    itemFlexGridSizer2->Add(itemFlexGridSizer3, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    wxStaticBox* itemStaticBoxSizer4Static = new wxStaticBox(itemPanel1, wxID_ANY, _("Behavior"));
    wxStaticBoxSizer* itemStaticBoxSizer4 = new wxStaticBoxSizer(itemStaticBoxSizer4Static, wxVERTICAL);
    itemFlexGridSizer3->Add(itemStaticBoxSizer4, 0, wxGROW|wxALIGN_TOP, 5);

    chkOverwriteExisting = new wxCheckBox( itemStaticBoxSizer4->GetStaticBox(), ID_OVERWRITE_EXISTING, _("Overwrite existing file(s)"), wxDefaultPosition, wxDefaultSize, 0 );
    chkOverwriteExisting->SetValue(false);
    itemStaticBoxSizer4->Add(chkOverwriteExisting, 0, wxALIGN_LEFT|wxALL, 5);

    chkCloseWhenDone = new wxCheckBox( itemStaticBoxSizer4->GetStaticBox(), ID_CLOSE_WHEN_DONE, _("Close desktop application after operation"), wxDefaultPosition, wxDefaultSize, 0 );
    chkCloseWhenDone->SetValue(false);
    itemStaticBoxSizer4->Add(chkCloseWhenDone, 0, wxALIGN_LEFT|wxLEFT|wxRIGHT|wxBOTTOM, 5);

    wxStaticBox* itemStaticBoxSizer7Static = new wxStaticBox(itemPanel1, wxID_ANY, _("Delete original file(s) after:"));
    wxStaticBoxSizer* itemStaticBoxSizer7 = new wxStaticBoxSizer(itemStaticBoxSizer7Static, wxVERTICAL);
    itemFlexGridSizer3->Add(itemStaticBoxSizer7, 0, wxGROW|wxALIGN_TOP, 5);

    wxFlexGridSizer* itemFlexGridSizer8 = new wxFlexGridSizer(0, 2, 0, 0);
    itemStaticBoxSizer7->Add(itemFlexGridSizer8, 0, wxGROW|wxLEFT|wxRIGHT, 5);

    itemFlexGridSizer8->Add(5, 5, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    chkDeleteAfterEncryption = new wxCheckBox( itemStaticBoxSizer7->GetStaticBox(), ID_DELETE_ENCRYPTION, _("Encryption"), wxDefaultPosition, wxDefaultSize, 0 );
    chkDeleteAfterEncryption->SetValue(false);
    itemFlexGridSizer8->Add(chkDeleteAfterEncryption, 0, wxALIGN_LEFT|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    itemFlexGridSizer8->AddGrowableCol(1);

    wxFlexGridSizer* itemFlexGridSizer11 = new wxFlexGridSizer(0, 2, 0, 0);
    itemStaticBoxSizer7->Add(itemFlexGridSizer11, 0, wxGROW|wxLEFT|wxRIGHT, 5);

    itemFlexGridSizer11->Add(5, 5, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    chkDeleteAfterDecryption = new wxCheckBox( itemStaticBoxSizer7->GetStaticBox(), ID_DELETE_ON_DECRYPTION, _("Decryption"), wxDefaultPosition, wxDefaultSize, 0 );
    chkDeleteAfterDecryption->SetValue(false);
    itemFlexGridSizer11->Add(chkDeleteAfterDecryption, 0, wxALIGN_LEFT|wxALIGN_CENTER_VERTICAL|wxLEFT|wxRIGHT|wxBOTTOM, 5);

    wxStaticBox* itemStaticBoxSizer14Static = new wxStaticBox(itemPanel1, wxID_ANY, _("Context Menu Support"));
    wxStaticBoxSizer* itemStaticBoxSizer14 = new wxStaticBoxSizer(itemStaticBoxSizer14Static, wxVERTICAL);
    itemFlexGridSizer3->Add(itemStaticBoxSizer14, 0, wxGROW|wxALIGN_TOP, 5);

    wxFlexGridSizer* itemFlexGridSizer15 = new wxFlexGridSizer(0, 3, 0, 0);
    itemStaticBoxSizer14->Add(itemFlexGridSizer15, 0, wxALIGN_LEFT|wxLEFT|wxTOP, 0);

    wxStaticText* itemStaticText16 = new wxStaticText( itemStaticBoxSizer14->GetStaticBox(), wxID_STATIC, _("Session timeout"), wxDefaultPosition, wxDefaultSize, 0 );
    itemFlexGridSizer15->Add(itemStaticText16, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxLEFT|wxTOP|wxBOTTOM, 5);

    edtTimeout = new wxTextCtrl( itemStaticBoxSizer14->GetStaticBox(), ID_TIMEOUT, wxEmptyString, wxDefaultPosition, wxSize(30, -1), 0 );
    edtTimeout->SetMaxLength(3);
    itemFlexGridSizer15->Add(edtTimeout, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    wxStaticText* itemStaticText18 = new wxStaticText( itemStaticBoxSizer14->GetStaticBox(), wxID_STATIC, _("minutes"), wxDefaultPosition, wxDefaultSize, 0 );
    itemFlexGridSizer15->Add(itemStaticText18, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxRIGHT|wxTOP|wxBOTTOM, 5);

    wxFlexGridSizer* itemFlexGridSizer19 = new wxFlexGridSizer(0, 2, 0, 0);
    itemStaticBoxSizer14->Add(itemFlexGridSizer19, 0, wxALIGN_LEFT|wxLEFT|wxTOP, 0);

    wxStaticText* itemStaticText20 = new wxStaticText( itemStaticBoxSizer14->GetStaticBox(), wxID_STATIC, _("Number of passes for Secure Delete"), wxDefaultPosition, wxDefaultSize, 0 );
    itemFlexGridSizer19->Add(itemStaticText20, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxLEFT|wxRIGHT|wxBOTTOM, 5);

    edtPasses = new wxTextCtrl( itemStaticBoxSizer14->GetStaticBox(), ID_PASSES, wxEmptyString, wxDefaultPosition, wxSize(30, -1), 0 );
    itemFlexGridSizer19->Add(edtPasses, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxLEFT|wxRIGHT|wxBOTTOM, 5);

    wxStaticBox* itemStaticBoxSizer22Static = new wxStaticBox(itemPanel1, wxID_ANY, _("Window"));
    wxStaticBoxSizer* itemStaticBoxSizer22 = new wxStaticBoxSizer(itemStaticBoxSizer22Static, wxVERTICAL);
    itemFlexGridSizer3->Add(itemStaticBoxSizer22, 0, wxGROW|wxALIGN_TOP, 5);

    wxFlexGridSizer* itemFlexGridSizer23 = new wxFlexGridSizer(0, 2, 0, 0);
    itemStaticBoxSizer22->Add(itemFlexGridSizer23, 0, wxALIGN_LEFT|wxALL, 5);

    itemFlexGridSizer23->Add(5, 5, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    chkOnTop = new wxCheckBox( itemStaticBoxSizer22->GetStaticBox(), ID_ON_TOP, _("Always on top"), wxDefaultPosition, wxDefaultSize, 0 );
    chkOnTop->SetValue(false);
    itemFlexGridSizer23->Add(chkOnTop, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    itemFlexGridSizer3->AddGrowableCol(0);
    itemFlexGridSizer3->AddGrowableCol(1);

    wxStaticBox* itemStaticBoxSizer26Static = new wxStaticBox(itemPanel1, wxID_ANY, _("File Compression Type"));
    wxStaticBoxSizer* itemStaticBoxSizer26 = new wxStaticBoxSizer(itemStaticBoxSizer26Static, wxVERTICAL);
    itemFlexGridSizer2->Add(itemStaticBoxSizer26, 0, wxGROW|wxALIGN_CENTER_VERTICAL, 5);

    wxArrayString cmbCompressionStrings;
    cmbCompressionStrings.Add(_("None"));
    cmbCompressionStrings.Add(_("zLib"));
    cmbCompressionStrings.Add(_("bZip"));
    cmbCompression = new wxChoice( itemStaticBoxSizer26->GetStaticBox(), ID_COMPRESSION, wxDefaultPosition, wxDefaultSize, cmbCompressionStrings, 0 );
    cmbCompression->SetStringSelection(_("None"));
    itemStaticBoxSizer26->Add(cmbCompression, 0, wxALIGN_LEFT|wxALL, 5);

    itemFlexGridSizer2->AddGrowableCol(0);

    // Set validators
    edtTimeout->SetValidator( wxTextValidator(wxFILTER_NONE, & ) );
    edtPasses->SetValidator( wxTextValidator(wxFILTER_NONE, & ) );
////@end VEILFilePropertyPage content construction
}


/*
 * Should we show tooltips?
 */

bool VEILFilePropertyPage::ShowToolTips()
{
    return true;
}

/*
 * Get bitmap resources
 */

wxBitmap VEILFilePropertyPage::GetBitmapResource( const wxString& name )
{
    // Bitmap retrieval
////@begin VEILFilePropertyPage bitmap retrieval
    wxUnusedVar(name);
    return wxNullBitmap;
////@end VEILFilePropertyPage bitmap retrieval
}

/*
 * Get icon resources
 */

wxIcon VEILFilePropertyPage::GetIconResource( const wxString& name )
{
    // Icon retrieval
////@begin VEILFilePropertyPage icon retrieval
    wxUnusedVar(name);
    return wxNullIcon;
////@end VEILFilePropertyPage icon retrieval
}


/*
 * wxEVT_COMMAND_CHECKBOX_CLICKED event handler for ID_OVERWRITE_EXISTING
 */

void VEILFilePropertyPage::OnOverwriteExistingClick( wxCommandEvent& event )
{
////@begin wxEVT_COMMAND_CHECKBOX_CLICKED event handler for ID_OVERWRITE_EXISTING in VEILFilePropertyPage.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_COMMAND_CHECKBOX_CLICKED event handler for ID_OVERWRITE_EXISTING in VEILFilePropertyPage. 
}


/*
 * wxEVT_COMMAND_CHECKBOX_CLICKED event handler for ID_CLOSE_WHEN_DONE
 */

void VEILFilePropertyPage::OnCloseWhenDoneClick( wxCommandEvent& event )
{
////@begin wxEVT_COMMAND_CHECKBOX_CLICKED event handler for ID_CLOSE_WHEN_DONE in VEILFilePropertyPage.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_COMMAND_CHECKBOX_CLICKED event handler for ID_CLOSE_WHEN_DONE in VEILFilePropertyPage. 
}


/*
 * wxEVT_COMMAND_CHECKBOX_CLICKED event handler for ID_DELETE_ENCRYPTION
 */

void VEILFilePropertyPage::OnDeleteEncryptionClick( wxCommandEvent& event )
{
////@begin wxEVT_COMMAND_CHECKBOX_CLICKED event handler for ID_DELETE_ENCRYPTION in VEILFilePropertyPage.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_COMMAND_CHECKBOX_CLICKED event handler for ID_DELETE_ENCRYPTION in VEILFilePropertyPage. 
}


/*
 * wxEVT_COMMAND_CHECKBOX_CLICKED event handler for ID_DELETE_ON_DECRYPTION
 */

void VEILFilePropertyPage::OnDeleteOnDecryptionClick( wxCommandEvent& event )
{
////@begin wxEVT_COMMAND_CHECKBOX_CLICKED event handler for ID_DELETE_ON_DECRYPTION in VEILFilePropertyPage.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_COMMAND_CHECKBOX_CLICKED event handler for ID_DELETE_ON_DECRYPTION in VEILFilePropertyPage. 
}


/*
 * wxEVT_COMMAND_TEXT_UPDATED event handler for ID_TIMEOUT
 */

void VEILFilePropertyPage::OnTimeoutTextUpdated( wxCommandEvent& event )
{
////@begin wxEVT_COMMAND_TEXT_UPDATED event handler for ID_TIMEOUT in VEILFilePropertyPage.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_COMMAND_TEXT_UPDATED event handler for ID_TIMEOUT in VEILFilePropertyPage. 
}


/*
 * wxEVT_COMMAND_CHECKBOX_CLICKED event handler for ID_ON_TOP
 */

void VEILFilePropertyPage::OnOnTopClick( wxCommandEvent& event )
{
////@begin wxEVT_COMMAND_CHECKBOX_CLICKED event handler for ID_ON_TOP in VEILFilePropertyPage.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_COMMAND_CHECKBOX_CLICKED event handler for ID_ON_TOP in VEILFilePropertyPage. 
}


/*
 * wxEVT_COMMAND_TEXT_UPDATED event handler for ID_PASSES
 */

void VEILFilePropertyPage::OnPassesTextUpdated( wxCommandEvent& event )
{
////@begin wxEVT_COMMAND_TEXT_UPDATED event handler for ID_PASSES in VEILFilePropertyPage.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_COMMAND_TEXT_UPDATED event handler for ID_PASSES in VEILFilePropertyPage. 
}


/*
 * wxEVT_COMMAND_CHOICE_SELECTED event handler for ID_COMPRESSION
 */

void VEILFilePropertyPage::OnCompressionSelected( wxCommandEvent& event )
{
////@begin wxEVT_COMMAND_CHOICE_SELECTED event handler for ID_COMPRESSION in VEILFilePropertyPage.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_COMMAND_CHOICE_SELECTED event handler for ID_COMPRESSION in VEILFilePropertyPage. 
}

