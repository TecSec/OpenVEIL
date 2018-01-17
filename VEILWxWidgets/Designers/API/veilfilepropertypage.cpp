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
    EVT_TEXT( ID_PASSES, VEILFilePropertyPage::OnPassesTextUpdated )
    EVT_CHECKBOX( ID_DELETE_ENCRYPTION, VEILFilePropertyPage::OnDeleteEncryptionClick )
    EVT_CHECKBOX( ID_DELETE_ON_DECRYPTION, VEILFilePropertyPage::OnDeleteOnDecryptionClick )
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

	SetBackgroundColour(wxColour(wxSystemSettingsNative::GetColour(wxSYS_COLOUR_3DFACE)));
	OnInitialize();
#ifdef __APPLE__
    edtPasses->SetFocus();
#endif // __APPLE__

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
    edtPasses = NULL;
    chkDeleteAfterEncryption = NULL;
    chkDeleteAfterDecryption = NULL;
    cmbCompression = NULL;
////@end VEILFilePropertyPage member initialisation
	m_nSecureDelete = 3;
	m_startOnLogin = false;
	m_bWindowsStart = false;
	m_CompType = 1;
	m_bDelAftEnc = false;
	m_bDelAftDec = false;
	m_bCertEnc = false;
	m_bCloseAft = false;
	m_bOverWrite = false;
	_bInitialized = false;
	_bDirty = false;
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
    chkCloseWhenDone->Show(false);
    itemStaticBoxSizer4->Add(chkCloseWhenDone, 0, wxALIGN_LEFT|wxLEFT|wxRIGHT|wxBOTTOM, 5);

    wxFlexGridSizer* itemFlexGridSizer7 = new wxFlexGridSizer(0, 2, 0, 0);
    itemStaticBoxSizer4->Add(itemFlexGridSizer7, 0, wxALIGN_LEFT|wxLEFT|wxTOP, 0);

    wxStaticText* itemStaticText8 = new wxStaticText( itemStaticBoxSizer4->GetStaticBox(), wxID_STATIC, _("Number of passes for Secure Delete"), wxDefaultPosition, wxDefaultSize, 0 );
    itemFlexGridSizer7->Add(itemStaticText8, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxLEFT|wxRIGHT|wxBOTTOM, 5);

    edtPasses = new wxTextCtrl( itemStaticBoxSizer4->GetStaticBox(), ID_PASSES, wxEmptyString, wxDefaultPosition, wxSize(30, -1), 0 );
    itemFlexGridSizer7->Add(edtPasses, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxLEFT|wxRIGHT|wxBOTTOM, 5);

    wxStaticBox* itemStaticBoxSizer10Static = new wxStaticBox(itemPanel1, wxID_ANY, _("Delete original file(s) after:"));
    wxStaticBoxSizer* itemStaticBoxSizer10 = new wxStaticBoxSizer(itemStaticBoxSizer10Static, wxVERTICAL);
    itemFlexGridSizer3->Add(itemStaticBoxSizer10, 0, wxGROW|wxALIGN_TOP, 5);

    wxFlexGridSizer* itemFlexGridSizer11 = new wxFlexGridSizer(0, 2, 0, 0);
    itemStaticBoxSizer10->Add(itemFlexGridSizer11, 0, wxGROW|wxLEFT|wxRIGHT, 5);

    itemFlexGridSizer11->Add(5, 5, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    chkDeleteAfterEncryption = new wxCheckBox( itemStaticBoxSizer10->GetStaticBox(), ID_DELETE_ENCRYPTION, _("Encryption"), wxDefaultPosition, wxDefaultSize, 0 );
    chkDeleteAfterEncryption->SetValue(false);
    itemFlexGridSizer11->Add(chkDeleteAfterEncryption, 0, wxALIGN_LEFT|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    itemFlexGridSizer11->Add(5, 5, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    chkDeleteAfterDecryption = new wxCheckBox( itemStaticBoxSizer10->GetStaticBox(), ID_DELETE_ON_DECRYPTION, _("Decryption"), wxDefaultPosition, wxDefaultSize, 0 );
    chkDeleteAfterDecryption->SetValue(false);
    itemFlexGridSizer11->Add(chkDeleteAfterDecryption, 0, wxALIGN_LEFT|wxALIGN_CENTER_VERTICAL|wxLEFT|wxRIGHT|wxBOTTOM, 5);

    itemFlexGridSizer11->AddGrowableCol(1);

    wxStaticBox* itemStaticBoxSizer16Static = new wxStaticBox(itemPanel1, wxID_ANY, _("File Compression Type"));
    wxStaticBoxSizer* itemStaticBoxSizer16 = new wxStaticBoxSizer(itemStaticBoxSizer16Static, wxVERTICAL);
    itemFlexGridSizer3->Add(itemStaticBoxSizer16, 0, wxGROW|wxALIGN_CENTER_VERTICAL, 5);

    wxArrayString cmbCompressionStrings;
    cmbCompressionStrings.Add(_("None"));
    cmbCompressionStrings.Add(_("zLib"));
    cmbCompressionStrings.Add(_("bZip"));
    cmbCompression = new wxChoice( itemStaticBoxSizer16->GetStaticBox(), ID_COMPRESSION, wxDefaultPosition, wxDefaultSize, cmbCompressionStrings, 0 );
    cmbCompression->SetStringSelection(_("None"));
    if (VEILFilePropertyPage::ShowToolTips())
        cmbCompression->SetToolTip(_("The type of compression that should be applied before data is encrypted."));
    itemStaticBoxSizer16->Add(cmbCompression, 0, wxALIGN_LEFT|wxALL, 5);

    itemFlexGridSizer3->Add(5, 5, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    itemFlexGridSizer3->AddGrowableCol(0);
    itemFlexGridSizer3->AddGrowableCol(1);

    itemFlexGridSizer2->AddGrowableCol(0);

    // Set validators
    edtPasses->SetValidator( wxTextValidator(wxFILTER_DIGITS, & _passesStr) );
	////@end VEILFilePropertyPage content construction
	Layout();
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
    return ::GetBitmapResource(name);
}

/*
 * Get icon resources
 */

wxIcon VEILFilePropertyPage::GetIconResource( const wxString& name )
{
    // Icon retrieval
    return ::GetIconResource(name);
}


/*
 * wxEVT_COMMAND_CHECKBOX_CLICKED event handler for ID_OVERWRITE_EXISTING
 */

void VEILFilePropertyPage::OnOverwriteExistingClick( wxCommandEvent& event )
{
    SetModified();
}


/*
 * wxEVT_COMMAND_CHECKBOX_CLICKED event handler for ID_CLOSE_WHEN_DONE
 */

void VEILFilePropertyPage::OnCloseWhenDoneClick( wxCommandEvent& event )
{
    SetModified();
}


/*
 * wxEVT_COMMAND_CHECKBOX_CLICKED event handler for ID_DELETE_ENCRYPTION
 */

void VEILFilePropertyPage::OnDeleteEncryptionClick( wxCommandEvent& event )
{
    SetModified();
}


/*
 * wxEVT_COMMAND_CHECKBOX_CLICKED event handler for ID_DELETE_ON_DECRYPTION
 */

void VEILFilePropertyPage::OnDeleteOnDecryptionClick( wxCommandEvent& event )
{
    SetModified();
}


/*
 * wxEVT_COMMAND_TEXT_UPDATED event handler for ID_PASSES
 */

void VEILFilePropertyPage::OnPassesTextUpdated( wxCommandEvent& event )
{
    if (TsStrToInt(edtPasses->GetValue().c_str().AsChar()) != m_nSecureDelete)
    {
        SetModified();
    }
}


/*
 * wxEVT_COMMAND_CHOICE_SELECTED event handler for ID_COMPRESSION
 */

void VEILFilePropertyPage::OnCompressionSelected( wxCommandEvent& event )
{
    if (cmbCompression->GetSelection() != m_CompType)
    {
        SetModified();
    }
}

void VEILFilePropertyPage::UpdateData(bool fromControls)
{
	if (fromControls)
	{
		Validate();
		TransferDataFromWindow();

		m_bOverWrite = chkOverwriteExisting->GetValue();
		m_bDelAftEnc = chkDeleteAfterEncryption->GetValue();
		m_bDelAftDec = chkDeleteAfterDecryption->GetValue();
		m_bCloseAft = chkCloseWhenDone->GetValue();
		m_nSecureDelete = TsStrToInt(edtPasses->GetValue().c_str().AsChar());
		m_CompType = cmbCompression->GetSelection();
	}
	else
	{
		DisablePolicyField(chkOverwriteExisting, _prefs->OverwriteExistingLocation());
		chkOverwriteExisting->SetValue(m_bOverWrite);

		DisablePolicyField(chkDeleteAfterEncryption, _prefs->DeleteAfterEncryptionLocation());
		chkDeleteAfterEncryption->SetValue(m_bDelAftEnc);

		DisablePolicyField(chkDeleteAfterDecryption, _prefs->DeleteAfterDecryptionLocation());
		chkDeleteAfterDecryption->SetValue(m_bDelAftDec);

		DisablePolicyField(chkCloseWhenDone, _prefs->CloseAfterOperationLocation());
		chkCloseWhenDone->SetValue(m_bCloseAft);

		DisablePolicyField(edtPasses, _prefs->SecureDeletePassCountLocation());
		_passesStr = (tscrypto::tsCryptoString().append(m_nSecureDelete)).c_str();
		edtPasses->SetValue(_passesStr);

		DisablePolicyField(cmbCompression, _prefs->CompressionTypeLocation());
		cmbCompression->SetSelection(m_CompType);
	}
}
void VEILFilePropertyPage::DisablePolicyField(wxWindow* hWnd, JsonConfigLocation location)
{
	if (hWnd != nullptr)
	{
		if (location == jc_Policy)
		{
			hWnd->Enable(false);
		}
		else
		{
			hWnd->Enable(true);
		}
	}
}
void VEILFilePropertyPage::OnInitialize()
{
	if (!_prefs)
	{
		_prefs = BasicVEILPreferences::Create();
		_prefs->loadValues();
		_prefs->StartMonitor();
	}

	Initialization();

	UpdateData(false);

	_bInitialized = true;
}
void VEILFilePropertyPage::Initialization()
{
	OnPrefChange();
}
void VEILFilePropertyPage::OnPrefChange()
{	//System

	m_bDelAftEnc = _prefs->getDeleteAfterEncryption();
	m_bDelAftDec = _prefs->getDeleteAfterDecryption();
	m_bOverWrite = _prefs->getOverwriteExisting();
	m_bCloseAft = _prefs->getCloseAfterOperation();
	m_nSecureDelete = _prefs->getSecureDeletePassCount();
	m_startOnLogin = false; // TODO: config.getNodeTextAsBool("Settings/StartWithWindows", false);
	m_CompType = _prefs->getCompressionType();

	// Set the controls

	_passesStr = (tscrypto::tsCryptoString().append(m_nSecureDelete)).c_str();

	// Update the page
	UpdateData(false);

}
void VEILFilePropertyPage::SetModified(bool bChanged)
{
	_bDirty = bChanged;
	std::shared_ptr<IVEILPropertySheet> sheet = _parentSheet.lock();
	if (!!sheet)
	{
		sheet->PageModified(bChanged);
	}
}
