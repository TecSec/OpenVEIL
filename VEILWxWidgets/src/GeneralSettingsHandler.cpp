//	Copyright (c) 2017, TecSec, Inc.
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

#include "stdafx.h"

/*!
 * Control identifiers
 */

 ////@begin control identifiers
#define ID_GENERALSETTINGSHANDLER 10000
#define ID_URL 10001
#define ID_USERNAME 10002
#define ID_ENCRYPTION 10003
#define ID_HASH 10004
#define ID_AIDLIST 10005
#define SYMBOL_GENERALSETTINGSHANDLER_STYLE wxCAPTION|wxRESIZE_BORDER|wxSYSTEM_MENU|wxCLOSE_BOX|wxTAB_TRAVERSAL|wxRAISED_BORDER
#define SYMBOL_GENERALSETTINGSHANDLER_TITLE _("GeneralSettingsHandler")
#define SYMBOL_GENERALSETTINGSHANDLER_IDNAME ID_GENERALSETTINGSHANDLER
#define SYMBOL_GENERALSETTINGSHANDLER_SIZE wxSize(460, 290)
#define SYMBOL_GENERALSETTINGSHANDLER_POSITION wxDefaultPosition
////@end control identifiers

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

class GeneralSettingsHandler : public IVEILPropertyPage, public tsmod::IObject, public wxPanel
{
	DECLARE_EVENT_TABLE()

public:
	GeneralSettingsHandler() : _parent(nullptr), _bDirty(false), /*_bCKMweb(false),*/ _Alg(_TS_ALG_ID::TS_ALG_AES_GCM_256),
		_HashAlg(_TS_ALG_ID::TS_ALG_SHA512), _bInitialized(false), _bDisplayMsgDlg(false)
	{
		Init();
	}
	virtual ~GeneralSettingsHandler() {}

	// wxPanel
	virtual bool Destroy() override
	{
		if (_parent != XP_WINDOW_INVALID)
			((wxWindow*)_parent)->RemoveChild(this);
		_parent = XP_WINDOW_INVALID;
		_parentSheet.reset();
		Me.reset();
		return true;
	}

	// Inherited via IVEILPropertyPage
	virtual tscrypto::tsCryptoString Title() const override
	{
		return "General";
	}
	virtual void SetParent(std::shared_ptr<IVEILPropertySheet> parentSheet)
	{
		_parentSheet = parentSheet;

		if (!!parentSheet)
		{
			_prefs = parentSheet->BasicPreferences();
		}
	}
	virtual XP_WINDOW CreatePage(XP_WINDOW parentWindow)
	{
		// Construct the dialog here
		Create((wxWindow*)parentWindow);

		OnInitialize();
		return (XP_WINDOW)(this);
	}

	virtual void OnHelp() override
	{
		//tscrypto::tsCryptoString path;
		//
		//if ( !xp_PathSearch("CKMDesktop.chm", path) )
		//{
		//	MessageBoxA(hWnd, "We were unable to locate the help file for the VEIL system.", "Error", MB_OK);
		//}
		//else
		//{
		//	//        TS_HtmlHelp(m_hWnd, path, HH_DISPLAY_TOC, 0);
		//	//		TS_HtmlHelp(m_hWnd, path, HH_DISPLAY_TOC, IDH_MNGT_CKMfile);
		//	TS_HtmlHelp((XP_WINDOW)hWnd, path, HH_HELP_CONTEXT, IDH_MNGT_GeneralTab);
		//}

		wxMessageBox("Help is not available at this time.", "Status", MB_OK);
	}
	virtual PPResult Apply() override
	{
		UpdateData(true);

		if (_prefs->EncryptionAlgorithmLocation() != jc_Policy)
			_prefs->setEncryptionAlgorithm(_Alg);
		if (_prefs->HashAlgorithmLocation() != jc_Policy)
			_prefs->setHashAlgorithm(_HashAlg);
		if (_prefs->KeyVEILUrlLocation() != jc_Policy)
			_prefs->setKeyVEILUrl(_url);
		if (_prefs->KeyVEILUsernameLocation() != jc_Policy)
			_prefs->setKeyVEILUsername(_username);
		if (_prefs->AIDListLocation() != jc_Policy)
			_prefs->setAIDList(_aidList);

		//desktop.setNodeItemAsNumber("Options", "EnableCkmWeb", _bCKMweb);
		_prefs->saveConfigurationChanges();

		UpdateData(false);

		SetModified(false);
		return NoError;
	}
	virtual bool KillActive() override
	{
		// Validate controls
		return false;
	}
	virtual bool QueryCancel() override
	{
		return false;
	}
	virtual bool QueryInitialFocus() override
	{
		return false;
	}
	virtual bool Reset() override
	{
		return false;
	}
	virtual bool SetActive() override
	{
		return false;
	}

protected:
	XP_WINDOW  _parent;
	std::shared_ptr<GeneralSettingsHandler> Me; // Keep me alive until Destroy is called
	tscrypto::tsCryptoString    _name;
	std::weak_ptr<IVEILPropertySheet> _parentSheet;
	std::shared_ptr<BasicVEILPreferences> _prefs;
	bool _bDirty;
	//bool _bCKMweb;
	TS_ALG_ID _Alg;
	TS_ALG_ID _HashAlg;
	bool _bInitialized;
	bool _bDisplayMsgDlg;
	tscrypto::tsCryptoString _url;
	tscrypto::tsCryptoString _username;
	tscrypto::tsCryptoString _aidList;

	void DisablePolicyField(wxWindow* hWnd, JsonConfigLocation location)
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
	void OnInitialize()
	{
		if (!_prefs)
		{
			_prefs = BasicVEILPreferences::Create();
			_prefs->loadValues();
			_prefs->StartMonitor();
		}

		Initialization();

		UpdateData(false);

		_bInitialized = TRUE;
	}
	void Initialization()
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
	void UpdateData(bool fromControls)
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
			_url = edtKeyVEILUrl->GetValue().mbc_str();
			_username = edtKeyVEILUsername->GetValue().mbc_str();
			_aidList = edtAIDList->GetValue().mbc_str();
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
	int FindAlgByID(TS_ALG_ID alg)
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
	int FindHashAlgByID(TS_ALG_ID alg)
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
	void SetModified(BOOL bChanged = TRUE)
	{
		_bDirty = bChanged != FALSE;
		std::shared_ptr<IVEILPropertySheet> sheet = _parentSheet.lock();
		if (!!sheet)
		{
			sheet->PageModified(bChanged != FALSE);
		}
	}

	/// Creation
	bool Create(wxWindow* parent, wxWindowID id = SYMBOL_GENERALSETTINGSHANDLER_IDNAME, const wxString& caption = SYMBOL_GENERALSETTINGSHANDLER_TITLE, const wxPoint& pos = SYMBOL_GENERALSETTINGSHANDLER_POSITION, const wxSize& size = SYMBOL_GENERALSETTINGSHANDLER_SIZE, long style = SYMBOL_GENERALSETTINGSHANDLER_STYLE)
	{
		Me = std::dynamic_pointer_cast<GeneralSettingsHandler>(_me.lock());

		////@begin GeneralSettingsHandler creation
		SetExtraStyle(wxWS_EX_VALIDATE_RECURSIVELY | wxWS_EX_BLOCK_EVENTS);
		wxPanel::Create(parent, id, pos, size, style);

		CreateControls();
		////@end GeneralSettingsHandler creation
		SetBackgroundColour(wxColour(wxSystemSettingsNative::GetColour(wxSYS_COLOUR_3DFACE)));

		OnInitialize();

		return true;
	}

	/// Initialises member variables
	void Init()
	{
		////@begin GeneralSettingsHandler member initialisation
		edtKeyVEILUrl = NULL;
		edtKeyVEILUsername = NULL;
		edtAIDList = NULL;
		cmbEncryption = NULL;
		cmbHash = NULL;
		////@end GeneralSettingsHandler member initialisation
	}

	/// Creates the controls and sizers
	void CreateControls()
	{
		////@begin GeneralSettingsHandler content construction
		GeneralSettingsHandler* itemPanel1 = this;

		wxFlexGridSizer* itemFlexGridSizer2 = new wxFlexGridSizer(0, 1, 0, 0);
		itemPanel1->SetSizer(itemFlexGridSizer2);

		wxStaticText* itemStaticText3 = new wxStaticText(itemPanel1, wxID_STATIC, _("KeyVEIL URL:"), wxDefaultPosition, wxDefaultSize, 0);
		itemFlexGridSizer2->Add(itemStaticText3, 0, wxALIGN_LEFT | wxALIGN_CENTER_VERTICAL | wxLEFT | wxRIGHT | wxTOP, 5);

		edtKeyVEILUrl = new wxTextCtrl(itemPanel1, ID_URL, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0);
		edtKeyVEILUrl->SetMaxLength(200);
		itemFlexGridSizer2->Add(edtKeyVEILUrl, 0, wxGROW | wxALIGN_CENTER_VERTICAL | wxALL, 5);

		wxStaticText* itemStaticText5 = new wxStaticText(itemPanel1, wxID_STATIC, _("Default KeyVEIL user name:"), wxDefaultPosition, wxDefaultSize, 0);
		itemFlexGridSizer2->Add(itemStaticText5, 0, wxALIGN_LEFT | wxALIGN_CENTER_VERTICAL | wxLEFT | wxRIGHT | wxTOP, 5);

		edtKeyVEILUsername = new wxTextCtrl(itemPanel1, ID_USERNAME, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0);
		edtKeyVEILUsername->SetMaxLength(50);
		itemFlexGridSizer2->Add(edtKeyVEILUsername, 0, wxGROW | wxALIGN_CENTER_VERTICAL | wxALL, 5);

		wxStaticText* itemStaticText7 = new wxStaticText(itemPanel1, wxID_STATIC, _("&Default Encryption Algorithm"), wxDefaultPosition, wxDefaultSize, 0);
		itemFlexGridSizer2->Add(itemStaticText7, 0, wxALIGN_LEFT | wxALIGN_CENTER_VERTICAL | wxLEFT | wxRIGHT | wxTOP, 5);

		wxFlexGridSizer* itemFlexGridSizer8 = new wxFlexGridSizer(0, 2, 0, 0);
		itemFlexGridSizer2->Add(itemFlexGridSizer8, 0, wxGROW | wxALIGN_CENTER_VERTICAL | wxLEFT | wxRIGHT | wxBOTTOM, 5);

		wxArrayString cmbEncryptionStrings;
		cmbEncryption = new wxChoice(itemPanel1, ID_ENCRYPTION, wxDefaultPosition, wxDefaultSize, cmbEncryptionStrings, 0);
		itemFlexGridSizer8->Add(cmbEncryption, 0, wxGROW | wxALIGN_CENTER_VERTICAL | wxRIGHT | wxTOP, 5);

		wxStaticText* itemStaticText10 = new wxStaticText(itemPanel1, wxID_STATIC, _("This algorithm is used by VEIL applications for data security."), wxDefaultPosition, wxDefaultSize, 0);
		itemStaticText10->Wrap(300);
		itemFlexGridSizer8->Add(itemStaticText10, 0, wxALIGN_CENTER_HORIZONTAL | wxALIGN_CENTER_VERTICAL | wxLEFT | wxRIGHT | wxTOP, 5);

		itemFlexGridSizer8->AddGrowableCol(0);

		wxStaticText* itemStaticText11 = new wxStaticText(itemPanel1, wxID_STATIC, _("Default Hash Algorithm:"), wxDefaultPosition, wxDefaultSize, 0);
		itemFlexGridSizer2->Add(itemStaticText11, 0, wxGROW | wxALIGN_CENTER_VERTICAL | wxLEFT | wxRIGHT | wxTOP, 5);

		wxFlexGridSizer* itemFlexGridSizer12 = new wxFlexGridSizer(0, 2, 0, 0);
		itemFlexGridSizer2->Add(itemFlexGridSizer12, 0, wxGROW | wxALIGN_CENTER_VERTICAL | wxLEFT | wxRIGHT | wxBOTTOM, 5);

		wxArrayString cmbHashStrings;
		cmbHash = new wxChoice(itemPanel1, ID_HASH, wxDefaultPosition, wxDefaultSize, cmbHashStrings, 0);
		itemFlexGridSizer12->Add(cmbHash, 0, wxGROW | wxALIGN_CENTER_VERTICAL | wxRIGHT | wxTOP, 5);

		wxStaticText* itemStaticText14 = new wxStaticText(itemPanel1, wxID_STATIC, _("This algorithm is used by VEIL applications for data integrity."), wxDefaultPosition, wxDefaultSize, 0);
		itemStaticText14->Wrap(300);
		itemFlexGridSizer12->Add(itemStaticText14, 0, wxALIGN_CENTER_HORIZONTAL | wxALIGN_CENTER_VERTICAL | wxLEFT | wxRIGHT | wxTOP, 5);

		itemFlexGridSizer12->AddGrowableCol(0);

		wxStaticText* itemStaticText15 = new wxStaticText(itemPanel1, wxID_STATIC, _("Enter the smart card identifiers (AIDs) that are to be supported:"), wxDefaultPosition, wxDefaultSize, 0);
		itemFlexGridSizer2->Add(itemStaticText15, 0, wxALIGN_LEFT | wxALIGN_CENTER_VERTICAL | wxALL, 5);

		edtAIDList = new wxTextCtrl(itemPanel1, ID_AIDLIST, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0);
		edtAIDList->SetMaxLength(500);
		edtAIDList->SetName(wxT("edtAIDList"));
		itemFlexGridSizer2->Add(edtAIDList, 0, wxGROW | wxALIGN_CENTER_VERTICAL | wxALL, 5);

		itemFlexGridSizer2->AddGrowableCol(0);

		////@end GeneralSettingsHandler content construction
	}
	/*
	* Get bitmap resources
	*/

	wxBitmap GetBitmapResource(const wxString& name)
	{
		return ::GetBitmapResource(name);
	}

	/*
	* Get icon resources
	*/

	wxIcon GetIconResource(const wxString& name)
	{
		return ::GetIconResource(name);
	}

	/// Should we show tooltips?
	static bool ShowToolTips()
	{
		return true;
	}
	/*
	 * wxEVT_COMMAND_CHOICE_SELECTED event handler for ID_ENCRYPTION
	 */

	void GeneralSettingsHandler::OnEncryptionSelected(wxCommandEvent& event)
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
			if (wxID_YES == wxMessageBox("Are you sure you want to change the default algorithm?", "VEIL General Settings", MB_YESNO | MB_ICONINFORMATION))
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

	void GeneralSettingsHandler::OnHashSelected(wxCommandEvent& event)
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
			if (wxID_YES == wxMessageBox("Are you sure you want to change the default hash algorithm?", "CKM Desktop Preferences", MB_YESNO | MB_ICONINFORMATION))
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
				if (index != CB_ERR)
					cmbHash->SetSelection(index);
				return;
			}
		}
		_HashAlg = newAlg;
		UpdateData(false);
	}

	void GeneralSettingsHandler::OnUrlTextUpdated(wxCommandEvent& event)
	{
		tscrypto::tsCryptoString tmp = edtKeyVEILUrl->GetValue().mbc_str();

		if (tmp == _url)
			return;

		if (_bInitialized)
		{
			_bDisplayMsgDlg = false;
			SetModified();
		}
	}

	void GeneralSettingsHandler::OnUsernameTextUpdated(wxCommandEvent& event)
	{
		tscrypto::tsCryptoString tmp = edtKeyVEILUsername->GetValue().mbc_str();

		if (tmp == _username)
			return;

		if (_bInitialized)
		{
			_bDisplayMsgDlg = false;
			SetModified();
		}
	}

	void GeneralSettingsHandler::OnAIDListUpdated(wxCommandEvent& event)
	{
		tscrypto::tsCryptoString tmp = edtAIDList->GetValue().mbc_str();

		if (tmp == _aidList)
			return;

		if (_bInitialized)
		{
			_bDisplayMsgDlg = false;
			SetModified();
		}
	}


private:
	////@begin GeneralSettingsHandler member variables
	wxTextCtrl* edtKeyVEILUrl;
	wxTextCtrl* edtKeyVEILUsername;
	wxTextCtrl* edtAIDList;
	wxChoice* cmbEncryption;
	wxChoice* cmbHash;
	////@end GeneralSettingsHandler member variables
};

/*
 * GeneralSettingsHandler event table definition
 */

BEGIN_EVENT_TABLE(GeneralSettingsHandler, wxPanel)

////@begin GeneralSettingsHandler event table entries
EVT_TEXT(ID_URL, GeneralSettingsHandler::OnUrlTextUpdated)
EVT_TEXT(ID_USERNAME, GeneralSettingsHandler::OnUsernameTextUpdated)
EVT_CHOICE(ID_ENCRYPTION, GeneralSettingsHandler::OnEncryptionSelected)
EVT_CHOICE(ID_HASH, GeneralSettingsHandler::OnHashSelected)
EVT_TEXT(ID_AIDLIST, GeneralSettingsHandler::OnAIDListUpdated)
////@end GeneralSettingsHandler event table entries


END_EVENT_TABLE()

tsmod::IObject* CreateGeneralSettingsPage()
{
	return dynamic_cast<tsmod::IObject*>(new GeneralSettingsHandler());
}