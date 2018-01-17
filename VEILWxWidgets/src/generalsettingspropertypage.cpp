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
 * GeneralSettingsPropertyPage type definition
 */

IMPLEMENT_DYNAMIC_CLASS( GeneralSettingsPropertyPage, wxPanel )


/*
 * GeneralSettingsPropertyPage event table definition
 */

BEGIN_EVENT_TABLE( GeneralSettingsPropertyPage, wxPanel )

////@begin GeneralSettingsPropertyPage event table entries
    EVT_TEXT( ID_URL, GeneralSettingsPropertyPage::OnUrlTextUpdated )
    EVT_TEXT( ID_USERNAME, GeneralSettingsPropertyPage::OnUsernameTextUpdated )
    EVT_CHOICE( ID_ENCRYPTION, GeneralSettingsPropertyPage::OnEncryptionSelected )
    EVT_CHOICE( ID_HASH, GeneralSettingsPropertyPage::OnHashSelected )
    EVT_TEXT( ID_APP_IDS, GeneralSettingsPropertyPage::OnAppIdsTextUpdated )
////@end GeneralSettingsPropertyPage event table entries

END_EVENT_TABLE()

const char *AlgNames[] =
{
	"AES GCM",
	"AES CBC",
	"DES3 CBC (three key)",
};

const TS_ALG_ID algIds[] =
{
	_TS_ALG_ID::TS_ALG_AES_GCM_256,
	_TS_ALG_ID::TS_ALG_AES_CBC_256,
	_TS_ALG_ID::TS_ALG_DES3_THREEKEY_CBC,
};

const char *HashAlgNames[] =
{
	"SHA-1",
	"SHA224",
	"SHA256",
	"SHA384",
	"SHA512",
};

const TS_ALG_ID hashAlgIds[] =
{
	_TS_ALG_ID::TS_ALG_SHA1,
	_TS_ALG_ID::TS_ALG_SHA224,
	_TS_ALG_ID::TS_ALG_SHA256,
	_TS_ALG_ID::TS_ALG_SHA384,
	_TS_ALG_ID::TS_ALG_SHA512,
};


/*
 * GeneralSettingsPropertyPage constructors
 */

GeneralSettingsPropertyPage::GeneralSettingsPropertyPage()
{
    Init();
}

GeneralSettingsPropertyPage::GeneralSettingsPropertyPage( wxWindow* parent, wxWindowID id, const wxString& caption, const wxPoint& pos, const wxSize& size, long style )
{
    Init();
    Create(parent, id, caption, pos, size, style);
}


/*
 * GeneralSettingsHandler creator
 */

bool GeneralSettingsPropertyPage::Create( wxWindow* parent, wxWindowID id, const wxString& caption, const wxPoint& pos, const wxSize& size, long style )
{
////@begin GeneralSettingsPropertyPage creation
    SetExtraStyle(wxWS_EX_VALIDATE_RECURSIVELY|wxWS_EX_BLOCK_EVENTS);
    wxPanel::Create( parent, id, pos, size, style );

    CreateControls();
    Centre();
////@end GeneralSettingsPropertyPage creation

    SetBackgroundColour(wxColour(wxSystemSettingsNative::GetColour(wxSYS_COLOUR_3DFACE)));
    OnInitialize();

    return true;
}


/*
 * GeneralSettingsPropertyPage destructor
 */

GeneralSettingsPropertyPage::~GeneralSettingsPropertyPage()
{
////@begin GeneralSettingsPropertyPage destruction
////@end GeneralSettingsPropertyPage destruction
}


/*
 * Member initialisation
 */

void GeneralSettingsPropertyPage::Init()
{
////@begin GeneralSettingsPropertyPage member initialisation
    edtKeyVEILUrl = NULL;
    edtKeyVEILUsername = NULL;
    cmbEncryption = NULL;
    cmbHash = NULL;
    edtAIDList = NULL;
////@end GeneralSettingsPropertyPage member initialisation
	_Alg = _TS_ALG_ID::TS_ALG_AES_GCM_256;
	_HashAlg = _TS_ALG_ID::TS_ALG_SHA512;
	_bDisplayMsgDlg = false;
	_bInitialized = false;
	_bDirty = false;
}


/*
 * Control creation for GeneralSettingsHandler
 */

void GeneralSettingsPropertyPage::CreateControls()
{    
////@begin GeneralSettingsPropertyPage content construction
    GeneralSettingsPropertyPage* itemPanel1 = this;

    wxFlexGridSizer* itemFlexGridSizer2 = new wxFlexGridSizer(0, 1, 0, 0);
    itemPanel1->SetSizer(itemFlexGridSizer2);

    wxStaticText* itemStaticText3 = new wxStaticText( itemPanel1, wxID_STATIC, _("VEIL URL (for Remote applications):"), wxDefaultPosition, wxDefaultSize, 0 );
    itemFlexGridSizer2->Add(itemStaticText3, 0, wxALIGN_LEFT|wxALIGN_CENTER_VERTICAL|wxLEFT|wxRIGHT|wxTOP, 5);

    edtKeyVEILUrl = new wxTextCtrl( itemPanel1, ID_URL, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
    edtKeyVEILUrl->SetMaxLength(200);
    if (GeneralSettingsPropertyPage::ShowToolTips())
        edtKeyVEILUrl->SetToolTip(_("Enter the URL to KeyVEIL (or this VEIL instance) for other applications to use to access the CKM system."));
    itemFlexGridSizer2->Add(edtKeyVEILUrl, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    wxStaticText* itemStaticText5 = new wxStaticText( itemPanel1, wxID_STATIC, _("Default KeyVEIL user name:"), wxDefaultPosition, wxDefaultSize, 0 );
    itemFlexGridSizer2->Add(itemStaticText5, 0, wxALIGN_LEFT|wxALIGN_CENTER_VERTICAL|wxLEFT|wxRIGHT|wxTOP, 5);

    edtKeyVEILUsername = new wxTextCtrl( itemPanel1, ID_USERNAME, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
    edtKeyVEILUsername->SetMaxLength(50);
    if (GeneralSettingsPropertyPage::ShowToolTips())
        edtKeyVEILUsername->SetToolTip(_("Enter the default username that shall be used for the VEIL/KeyVEIL entered above."));
    itemFlexGridSizer2->Add(edtKeyVEILUsername, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    wxStaticText* itemStaticText7 = new wxStaticText( itemPanel1, wxID_STATIC, _("&Default Encryption Algorithm"), wxDefaultPosition, wxDefaultSize, 0 );
    itemFlexGridSizer2->Add(itemStaticText7, 0, wxALIGN_LEFT|wxALIGN_CENTER_VERTICAL|wxLEFT|wxRIGHT|wxTOP, 5);

    wxFlexGridSizer* itemFlexGridSizer8 = new wxFlexGridSizer(0, 2, 0, 0);
    itemFlexGridSizer2->Add(itemFlexGridSizer8, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxLEFT|wxRIGHT|wxBOTTOM, 5);

    wxArrayString cmbEncryptionStrings;
    cmbEncryption = new wxChoice( itemPanel1, ID_ENCRYPTION, wxDefaultPosition, wxDefaultSize, cmbEncryptionStrings, 0 );
    if (GeneralSettingsPropertyPage::ShowToolTips())
        cmbEncryption->SetToolTip(_("Select the default encryption algorithm that is to be used when data is encrypted."));
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
    if (GeneralSettingsPropertyPage::ShowToolTips())
        cmbHash->SetToolTip(_("Select the default hash algorithm that is to be used for data integrity when data is encrypted."));
    itemFlexGridSizer12->Add(cmbHash, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxRIGHT|wxTOP, 5);

    wxStaticText* itemStaticText14 = new wxStaticText( itemPanel1, wxID_STATIC, _("This algorithm is used by VEIL applications for data integrity."), wxDefaultPosition, wxDefaultSize, 0 );
    itemStaticText14->Wrap(300);
    itemFlexGridSizer12->Add(itemStaticText14, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxLEFT|wxRIGHT|wxTOP, 5);

    itemFlexGridSizer12->AddGrowableCol(0);

    wxStaticText* itemStaticText15 = new wxStaticText( itemPanel1, wxID_STATIC, _("Enter the smart card identifiers (AIDs) that are to be supported:"), wxDefaultPosition, wxDefaultSize, 0 );
    itemFlexGridSizer2->Add(itemStaticText15, 0, wxALIGN_LEFT|wxALIGN_CENTER_VERTICAL|wxLEFT|wxRIGHT|wxTOP, 5);

    edtAIDList = new wxTextCtrl( itemPanel1, ID_APP_IDS, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
    edtAIDList->SetMaxLength(500);
    if (GeneralSettingsPropertyPage::ShowToolTips())
        edtAIDList->SetToolTip(_("Enter the list of Smart Card AIDs that are to be used by VEIL.  Each AID is a series of 10 - 32 hex digits.  Each AID is separated from the next with a semicolon."));
    itemFlexGridSizer2->Add(edtAIDList, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    itemFlexGridSizer2->AddGrowableCol(0);

////@end GeneralSettingsPropertyPage content construction
	Layout();
}


/*
 * Should we show tooltips?
 */

bool GeneralSettingsPropertyPage::ShowToolTips()
{
    return true;
}

/*
 * Get bitmap resources
 */

wxBitmap GeneralSettingsPropertyPage::GetBitmapResource( const wxString& name )
{
    // Bitmap retrieval
    return ::GetBitmapResource(name);
}

/*
 * Get icon resources
 */

wxIcon GeneralSettingsPropertyPage::GetIconResource( const wxString& name )
{
    // Icon retrieval
    return ::GetIconResource(name);
}


/*
 * wxEVT_COMMAND_CHOICE_SELECTED event handler for ID_ENCRYPTION
 */

void GeneralSettingsPropertyPage::OnEncryptionSelected( wxCommandEvent& event )
{
    TS_ALG_ID newAlg;
    int index;

    index = cmbEncryption->GetSelection();
    if (index < 0)
        return;

    newAlg = (TS_ALG_ID)(int)(intptr_t)cmbEncryption->GetClientData(index);

    if (newAlg == _Alg)
        return;

    if (_bInitialized)
    {
        if (wxID_YES == wxTsMessageBox("Are you sure you want to change the default algorithm?", "VEIL General Settings", wxYES_NO | wxICON_INFORMATION))
        {
            _bDisplayMsgDlg = false;
            ///
            //m_bInitialized = false;
            ///
            SetModified();
        }
        else
        {
            index = FindAlgByID(_Alg);
            if (index >= 0)
                cmbEncryption->SetSelection(index);
            return;
        }
    }
    _Alg = newAlg;
    UpdateData(false);
}


/*
 * wxEVT_COMMAND_CHOICE_SELECTED event handler for ID_HASH
 */

void GeneralSettingsPropertyPage::OnHashSelected( wxCommandEvent& event )
{
    TS_ALG_ID newAlg;
    int index;

    index = cmbHash->GetSelection();
    if (index < 0)
        return;

    newAlg = (TS_ALG_ID)(int)(intptr_t)cmbHash->GetClientData(index);

    if (newAlg == _HashAlg)
        return;

    if (_bInitialized)
    {
        if (wxID_YES == wxTsMessageBox("Are you sure you want to change the default hash algorithm?", "CKM Desktop Preferences", wxYES_NO | wxICON_INFORMATION))
        {
            _bDisplayMsgDlg = false;
            ///
            //m_bInitialized = false;
            ///
            SetModified();
        }
        else
        {
            index = FindHashAlgByID(_HashAlg);
            if (index != -1)
                cmbHash->SetSelection(index);
            return;
        }
    }
    _HashAlg = newAlg;
    UpdateData(false);
}


/*
 * wxEVT_COMMAND_TEXT_UPDATED event handler for ID_URL
 */

void GeneralSettingsPropertyPage::OnUrlTextUpdated( wxCommandEvent& event )
{
    tscrypto::tsCryptoString tmp = edtKeyVEILUrl->GetValue().c_str().AsChar();

    if (tmp == _url)
        return;

    if (_bInitialized)
    {
        _bDisplayMsgDlg = false;
        SetModified();
    }
}


/*
 * wxEVT_COMMAND_TEXT_UPDATED event handler for ID_USERNAME
 */

void GeneralSettingsPropertyPage::OnUsernameTextUpdated( wxCommandEvent& event )
{
	tscrypto::tsCryptoString tmp = edtKeyVEILUsername->GetValue().c_str().AsChar();

	if (tmp == _username)
		return;

	if (_bInitialized)
	{
		_bDisplayMsgDlg = false;
		SetModified();
	}
}


/*
 * wxEVT_COMMAND_TEXT_UPDATED event handler for ID_TEXTCTRL
 */

void GeneralSettingsPropertyPage::OnAppIdsTextUpdated( wxCommandEvent& event )
{
	tscrypto::tsCryptoString tmp = edtAIDList->GetValue().c_str().AsChar();

	if (tmp == _aidList)
		return;

	if (_bInitialized)
	{
		_bDisplayMsgDlg = false;
		SetModified();
	}
}

void GeneralSettingsPropertyPage::DisablePolicyField(wxWindow* hWnd, JsonConfigLocation location)
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
void GeneralSettingsPropertyPage::OnInitialize()
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
void GeneralSettingsPropertyPage::Initialization()
{
	int index;

	_Alg = _prefs->getEncryptionAlgorithm();
	_HashAlg = _prefs->getHashAlgorithm();
	_url = _prefs->getKeyVEILUrl();
	_username = _prefs->getKeyVEILUsername();
	_aidList = _prefs->getAIDList();

	DisablePolicyField(cmbEncryption, _prefs->EncryptionAlgorithmLocation());
	DisablePolicyField(cmbHash, _prefs->HashAlgorithmLocation());
	DisablePolicyField(edtKeyVEILUrl, _prefs->KeyVEILUrlLocation());
	DisablePolicyField(edtKeyVEILUsername, _prefs->KeyVEILUsernameLocation());
	DisablePolicyField(edtAIDList, _prefs->AIDListLocation());

	cmbEncryption->Clear();
	for (int i = 0; i < (int)(sizeof(AlgNames) / sizeof(AlgNames[0])); i++)
	{
		cmbEncryption->Append(AlgNames[i], (void*)(intptr_t)algIds[i]);
	}
	index = FindAlgByID(_Alg);
	if (index != -1)
		cmbEncryption->SetSelection(index);

	cmbHash->Clear();
	for (int i = 0; i < (int)(sizeof(HashAlgNames) / sizeof(HashAlgNames[0])); i++)
	{
		cmbHash->Append(HashAlgNames[i], (void*)(intptr_t)hashAlgIds[i]);
	}
	index = FindHashAlgByID(_HashAlg);
	if (index != -1)
		cmbHash->SetSelection(index);

	edtKeyVEILUrl->SetValue(_url.c_str());
	edtKeyVEILUsername->SetValue(_username.c_str());
	edtAIDList->SetValue(_aidList.c_str());

	//
	//m_bDisplayMsgDlg = TRUE;


	// TM Setting
	//_bCKMweb = (config.getNodeItemAsNumber("Options", "EnableCkmWeb", 0) != 0);
	// testing

	//        GetDlgItem(IDC_CKMDESKTOP_CHECK)->EnableWindow(!m_filePrefs->getIsStartWithWindowsFromPolicy());
	//        GetDlgItem(IDC_SEC_DEL_PASSES_STATIC)->EnableWindow(!m_psysPrefs->getIsSecureDeleteCountPassFromPolicy());
	//        GetDlgItem(IDC_ALG_COMBO)->EnableWindow(!m_psysPrefs->getIsDefaultEncryptAlgFromPolicy());


	UpdateData(false);
}
void GeneralSettingsPropertyPage::UpdateData(bool fromControls)
{
	int index;

	if (fromControls)
	{
		//m_bCKMweb = (SendDlgItemMessage(m_hWnd, IDC_TM_CHECK, BM_GETCHECK, 0, 0) == BST_CHECKED);
		index = cmbEncryption->GetSelection();
		if (index >= 0)
		{
			_Alg = (TS_ALG_ID)(int)(intptr_t)cmbEncryption->GetClientData(index);
		}
		else
		{
			_Alg = _TS_ALG_ID::TS_ALG_AES_GCM_256;
		}
		index = cmbHash->GetSelection();
		if (index >= 0)
		{
			_HashAlg = (TS_ALG_ID)(int)(intptr_t)cmbHash->GetClientData(index);
		}
		else
		{
			_HashAlg = _TS_ALG_ID::TS_ALG_SHA512;
		}
		_url = edtKeyVEILUrl->GetValue().c_str().AsChar();
		_username = edtKeyVEILUsername->GetValue().c_str().AsChar();
		_aidList = edtAIDList->GetValue().c_str().AsChar();
	}
	else
	{
		//SendDlgItemMessage(m_hWnd, IDC_TM_CHECK, BM_SETCHECK, (m_bCKMweb) ? BST_CHECKED : BST_UNCHECKED, 0);
		index = FindAlgByID(_Alg);
		cmbEncryption->SetSelection(index);
		index = FindHashAlgByID(_HashAlg);
		cmbHash->SetSelection(index);
		edtKeyVEILUrl->SetValue(_url.c_str());
		edtKeyVEILUsername->SetValue(_username.c_str());
		edtAIDList->SetValue(_aidList.c_str());
	}
}
int GeneralSettingsPropertyPage::FindAlgByID(TS_ALG_ID alg)
{
	int count = cmbEncryption->GetCount();
	int i;

	for (i = 0; i < count; i++)
	{
		if ((TS_ALG_ID)(int)(intptr_t)cmbEncryption->GetClientData(i) == alg)
			return i;
	}
	return -1;
}
int GeneralSettingsPropertyPage::FindHashAlgByID(TS_ALG_ID alg)
{
	int count = cmbHash->GetCount();
	int i;

	for (i = 0; i < count; i++)
	{
		if ((TS_ALG_ID)(int)(intptr_t)cmbHash->GetClientData(i) == alg)
			return i;
	}
	return -1;
}
void GeneralSettingsPropertyPage::SetModified(bool bChanged)
{
	_bDirty = bChanged != false;
	std::shared_ptr<IVEILPropertySheet> sheet = _parentSheet.lock();
	if (!!sheet)
	{
		sheet->PageModified(bChanged != false);
	}
}
