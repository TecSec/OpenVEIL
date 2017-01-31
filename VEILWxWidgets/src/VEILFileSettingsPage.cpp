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
#define ID_VEILFILEPROPERTYPAGE 10000
#define ID_OVERWRITE_EXISTING 10003
#define ID_CLOSE_WHEN_DONE 10004
#define ID_DELETE_ENCRYPTION 10005
#define ID_DELETE_ON_DECRYPTION 10006
#define ID_TIMEOUT 10010
#define ID_PASSES 10011
#define ID_ON_TOP 10012
#define ID_COMPRESSION 10009
#define SYMBOL_VEILFILEPROPERTYPAGE_STYLE wxCAPTION|wxRESIZE_BORDER|wxSYSTEM_MENU|wxCLOSE_BOX|wxTAB_TRAVERSAL|wxRAISED_BORDER
#define SYMBOL_VEILFILEPROPERTYPAGE_TITLE _("VEILFilePropertyPage")
#define SYMBOL_VEILFILEPROPERTYPAGE_IDNAME ID_VEILFILEPROPERTYPAGE
#define SYMBOL_VEILFILEPROPERTYPAGE_SIZE wxSize(460, 290)
#define SYMBOL_VEILFILEPROPERTYPAGE_POSITION wxDefaultPosition
////@end control identifiers


class VEILFileSettingsPage : public IVEILPropertyPage, public tsmod::IObject, public wxPanel
{
	DECLARE_EVENT_TABLE()

public:
	VEILFileSettingsPage() :
		m_bDelAftEnc(false),
		m_bDelAftSig(false),
		m_bDelAftDec(false),
		m_bCertEnc(false),
		m_bCloseAft(false),
		m_bOverWrite(false),
		m_nTimeOut(0),
		m_bDirty(false),
		m_nSecureDelete(3),
		m_startOnLogin(false),
		m_bWindowsStart(false),
		m_bAlwaysOnTop(false),
		//m_nPosLeft(0),
		//m_nPosTop(0),
		m_CompType(ct_None),
		_parent(nullptr),
		_bDirty(false),
		_bInitialized(false),
		_bDisplayMsgDlg(false)
	{
		Init();
	}
	virtual ~VEILFileSettingsPage() {}

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
		return "FileVEIL";
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
		//		// Get the values from the dialog
		//		UpdateData(true);
		//		// Get the values of the controls
		//
		//		UINT nTimeout = m_nTimeOut * 60;
		////		POINT winPt = { (LONG)m_nPosLeft, (LONG)m_nPosTop };
		//
		//		_prefs->setAlwaysOnTop(m_bAlwaysOnTop ? true : false);
		//		_prefs->setDeleteAfterEncryption(m_bDelAftEnc ? true : false);
		//		_prefs->setDeleteAfterSigning(m_bDelAftSig ? true : false);
		//		_prefs->setDeleteAfterDecryption(m_bDelAftDec ? true : false);
		//		_prefs->setOverwriteExisting(m_bOverWrite ? true : false);
		//		_prefs->setCloseAfterOperation(m_bCloseAft ? true : false);
		//		_prefs->setSecureDeletePassCount(m_nSecureDelete);
		//		_prefs->setSessionTimeout(nTimeout);
		//		_prefs->setCompressionType((CompressionType)m_CompType);
		//		//_prefs->setWindowPosition(winPt);
		//
		//		//        config.setNodeTextAsBool("Settings/AllowCertEncryption", (m_bCertEnc ? true : false));
		//		//        config.setNodeTextAsNumber("Settings/StartWithWindows", m_startOnLogin);
		//
		//		_prefs->saveConfigurationChanges();
		//
		//		//if (m_bWindowsStart)
		//		//{
		//		//	if (m_startOnLogin)
		//		//	{
		//		//		StartWindowWindows();
		//		//	}
		//		//	else
		//		//	{
		//		//		DontStartWindowWindows();
		//		//	}
		//		//}
		//
		//		SetModified(false);
		//		return true;



		UpdateData(true);


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
	std::shared_ptr<VEILFileSettingsPage> Me; // Keep me alive until Destroy is called
	tscrypto::tsCryptoString    _name;
	std::weak_ptr<IVEILPropertySheet> _parentSheet;
	std::shared_ptr<BasicVEILPreferences> _prefs;
	bool _bDirty;
	bool _bInitialized;
	bool _bDisplayMsgDlg;
	bool m_bDirty;
	int m_nSecureDelete;
	bool m_startOnLogin;
	bool m_bWindowsStart;
	//	CkmCompressionType m_Compress;
	int m_CompType;
	bool	m_bDelAftEnc;
	bool	m_bDelAftSig;
	bool	m_bDelAftDec;
	bool	m_bCertEnc;
	bool	m_bCloseAft;
	bool	m_bOverWrite;
	UINT	m_nTimeOut;
	bool	m_bAlwaysOnTop;
	//UINT	m_nPosLeft;
	//UINT	m_nPosTop;
	wxString _passesStr;
	wxString _timeoutStr;

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

		_bInitialized = true;
	}
	void Initialization()
	{
		OnPrefChange();
	}
	void OnPrefChange()
	{	//System

		m_bAlwaysOnTop = _prefs->getAlwaysOnTop();
		m_bDelAftEnc = _prefs->getDeleteAfterEncryption();
		m_bDelAftSig = _prefs->getDeleteAfterSigning();
		m_bDelAftDec = _prefs->getDeleteAfterDecryption();
		m_bOverWrite = _prefs->getOverwriteExisting();
		m_bCloseAft = _prefs->getCloseAfterOperation();
		//m_bCertEnc	 = false;  // TODO:  config.getNodeTextAsBool("Settings/AllowCertEncryption", false);
		m_nSecureDelete = _prefs->getSecureDeletePassCount();
		UINT nTimeout = _prefs->getSessionTimeout();
		m_startOnLogin = false; // TODO: config.getNodeTextAsBool("Settings/StartWithWindows", false);
		m_CompType = _prefs->getCompressionType();
		//m_nPosLeft = _prefs->getWindowPosition().x;
		//m_nPosTop = _prefs->getWindowPosition().y;

		// Set the controls

		m_nTimeOut = nTimeout / 60;

		_timeoutStr = (tscrypto::tsCryptoString() << m_nTimeOut).c_str();
		_passesStr = (tscrypto::tsCryptoString() << m_nSecureDelete).c_str();

		//SendDlgItemMessage(m_hWnd, IDC_POSLEFT, EM_SETLIMITTEXT, 3, 0);
		//SendDlgItemMessage(m_hWnd, IDC_POSTOP, EM_SETLIMITTEXT, 3, 0);

		// Update the page
		UpdateData(false);

	}
	void UpdateData(bool fromControls)
	{
		if (fromControls)
		{
			Validate();
			TransferDataFromWindow();

			m_bOverWrite = chkOverwriteExisting->GetValue();
			m_bDelAftEnc = chkDeleteAfterEncryption->GetValue();
			//m_bDelAftSig = (SendDlgItemMessage(m_hWnd, IDC_DEL_AFT_SIG_CHK, BM_GETCHECK, 0, 0) == BST_CHECKED);
			m_bDelAftDec = chkDeleteAfterDecryption->GetValue();
			//            m_bCertEnc = (SendDlgItemMessage(m_hWnd, IDC_ALLOW_CERT_ENC_CHK, BM_GETCHECK, 0, 0) == BST_CHECKED);
			m_bCloseAft = chkCloseWhenDone->GetValue();
			m_nTimeOut = TsStrToInt(edtTimeout->GetValue().mbc_str());
			m_nSecureDelete = TsStrToInt(edtPasses->GetValue().mbc_str());
			//            m_startOnLogin = (SendDlgItemMessage(m_hWnd, IDC_CKMFILE_CHECK, BM_GETCHECK, 0, 0) == BST_CHECKED);
			m_bAlwaysOnTop = chkOnTop->GetValue();

			m_CompType = cmbCompression->GetSelection();

			//SendDlgItemMessage(m_hWnd, IDC_POSLEFT, WM_GETTEXT, sizeof(buff), (LPARAM)buff);
			//m_nPosLeft = TsStrToInt(buff);
			//buff[0] = 0;
			//SendDlgItemMessage(m_hWnd, IDC_POSTOP, WM_GETTEXT, sizeof(buff), (LPARAM)buff);
			//m_nPosTop = TsStrToInt(buff);
		}
		else
		{
			DisablePolicyField(chkOverwriteExisting, _prefs->OverwriteExistingLocation());
			chkOverwriteExisting->SetValue(m_bOverWrite);

			DisablePolicyField(chkDeleteAfterEncryption, _prefs->DeleteAfterEncryptionLocation());
			chkDeleteAfterEncryption->SetValue(m_bDelAftEnc);

			//DisablePolicyField(IDC_DEL_AFT_SIG_CHK, _prefs->DeleteAfterSignatureLocation());
			//SendDlgItemMessage(m_hWnd, IDC_DEL_AFT_SIG_CHK, BM_SETCHECK, (m_bDelAftSig ? BST_CHECKED : BST_UNCHECKED), 0);

			DisablePolicyField(chkDeleteAfterDecryption, _prefs->DeleteAfterDecryptionLocation());
			chkDeleteAfterDecryption->SetValue(m_bDelAftDec);

			//DisablePolicyField(IDC_ALLOW_CERT_ENC_CHK, _prefs->xxxLocation());
			//            SendDlgItemMessage(m_hWnd, IDC_ALLOW_CERT_ENC_CHK, BM_SETCHECK, (m_bCertEnc ? BST_CHECKED : BST_UNCHECKED), 0);

			DisablePolicyField(chkCloseWhenDone, _prefs->CloseAfterOperationLocation());
			chkCloseWhenDone->SetValue(m_bCloseAft);

			DisablePolicyField(edtTimeout, _prefs->SessionTimeoutLocation());
			_timeoutStr = (tscrypto::tsCryptoString() << m_nTimeOut).c_str();
			edtTimeout->SetValue(_timeoutStr);

			DisablePolicyField(edtPasses, _prefs->SecureDeletePassCountLocation());
			_passesStr = (tscrypto::tsCryptoString() << m_nSecureDelete).c_str();
			edtPasses->SetValue(_passesStr);

			// DisablePolicyField(IDC_CKMFILE_CHECK, _prefs->xxxLocation());
			//            SendDlgItemMessage(m_hWnd, IDC_CKMFILE_CHECK, BM_SETCHECK, (m_startOnLogin) ? BST_CHECKED : BST_UNCHECKED, 0);

			DisablePolicyField(chkOnTop, _prefs->AlwaysOnTopLocation());
			chkOnTop->SetValue(m_bAlwaysOnTop);

			//TsSnPrintf(buff, sizeof(buff) / sizeof(buff[0]), ("%d"), m_nPosLeft);
			////DisablePolicyField(IDC_POSLEFT, _prefs->());
			//SendDlgItemMessage(m_hWnd, IDC_POSLEFT, WM_SETTEXT, 0, (LPARAM)buff);
			//
			//TsSnPrintf(buff, sizeof(buff) / sizeof(buff[0]), ("%d"), m_nPosTop);
			////DisablePolicyField(IDC_POSTOP, _prefs->());
			//SendDlgItemMessage(m_hWnd, IDC_POSTOP, WM_SETTEXT, 0, (LPARAM)buff);

			DisablePolicyField(cmbCompression, _prefs->CompressionTypeLocation());
			cmbCompression->SetSelection(m_CompType);
		}
	}
	void SetModified(bool bChanged = true)
	{
		_bDirty = bChanged;
		std::shared_ptr<IVEILPropertySheet> sheet = _parentSheet.lock();
		if (!!sheet)
		{
			sheet->PageModified(bChanged);
		}
	}

	/// Creation
	bool Create(wxWindow* parent, wxWindowID id = SYMBOL_VEILFILEPROPERTYPAGE_IDNAME, const wxString& caption = SYMBOL_VEILFILEPROPERTYPAGE_TITLE, const wxPoint& pos = SYMBOL_VEILFILEPROPERTYPAGE_POSITION, const wxSize& size = SYMBOL_VEILFILEPROPERTYPAGE_SIZE, long style = SYMBOL_VEILFILEPROPERTYPAGE_STYLE)
	{
		Me = std::dynamic_pointer_cast<VEILFileSettingsPage>(_me.lock());

		////@begin VEILFilePropertyPage creation
		SetExtraStyle(wxWS_EX_VALIDATE_RECURSIVELY | wxWS_EX_BLOCK_EVENTS);
		wxPanel::Create(parent, id, pos, size, style);

		CreateControls();
		Centre();
		////@end VEILFilePropertyPage creation

		SetBackgroundColour(wxColour(wxSystemSettingsNative::GetColour(wxSYS_COLOUR_3DFACE)));
		OnInitialize();

		return true;
	}

	/// Initialises member variables
	void Init()
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

	/// Creates the controls and sizers
	void CreateControls()
	{
		////@begin VEILFilePropertyPage content construction
		VEILFileSettingsPage* itemPanel1 = this;

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

		////@end VEILFilePropertyPage content construction
		edtPasses->SetValidator(wxTextValidator(wxFILTER_DIGITS, &_passesStr));
		edtTimeout->SetValidator(wxTextValidator(wxFILTER_DIGITS, &_timeoutStr));
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


	////@begin VEILFilePropertyPage event handler declarations

		/// wxEVT_COMMAND_CHECKBOX_CLICKED event handler for ID_OVERWRITE_EXISTING
	void OnOverwriteExistingClick(wxCommandEvent& event)
	{
		SetModified();
	}

	/// wxEVT_COMMAND_CHECKBOX_CLICKED event handler for ID_CLOSE_WHEN_DONE
	void OnCloseWhenDoneClick(wxCommandEvent& event)
	{
		SetModified();
	}

	/// wxEVT_COMMAND_CHECKBOX_CLICKED event handler for ID_DELETE_ENCRYPTION
	void OnDeleteEncryptionClick(wxCommandEvent& event)
	{
		SetModified();
	}

	/// wxEVT_COMMAND_CHECKBOX_CLICKED event handler for ID_DELETE_ON_DECRYPTION
	void OnDeleteOnDecryptionClick(wxCommandEvent& event)
	{
		SetModified();
	}

	/// wxEVT_COMMAND_TEXT_UPDATED event handler for ID_TIMEOUT
	void OnTimeoutTextUpdated(wxCommandEvent& event)
	{
		if (TsStrToInt(edtTimeout->GetValue().mbc_str()) != m_nTimeOut)
		{
			SetModified();
		}
	}

	/// wxEVT_COMMAND_TEXT_UPDATED event handler for ID_PASSES
	void OnPassesTextUpdated(wxCommandEvent& event)
	{
		if (TsStrToInt(edtPasses->GetValue().mbc_str()) != m_nSecureDelete)
		{
			SetModified();
		}
	}

	/// wxEVT_COMMAND_CHECKBOX_CLICKED event handler for ID_ON_TOP
	void OnOnTopClick(wxCommandEvent& event)
	{
		SetModified();
	}

	/// wxEVT_COMMAND_CHOICE_SELECTED event handler for ID_COMPRESSION
	void OnCompressionSelected(wxCommandEvent& event)
	{
		if (cmbCompression->GetSelection() != m_CompType)
		{
			SetModified();
		}
	}

	////@end VEILFilePropertyPage event handler declarations

private:
	////@begin VEILFilePropertyPage member variables
	wxCheckBox* chkOverwriteExisting;
	wxCheckBox* chkCloseWhenDone;
	wxCheckBox* chkDeleteAfterEncryption;
	wxCheckBox* chkDeleteAfterDecryption;
	wxTextCtrl* edtTimeout;
	wxTextCtrl* edtPasses;
	wxCheckBox* chkOnTop;
	wxChoice* cmbCompression;
	////@end VEILFilePropertyPage member variables
};

/*
 * GeneralSettingsHandler event table definition
 */

BEGIN_EVENT_TABLE(VEILFileSettingsPage, wxPanel)

////@begin VEILFilePropertyPage event table entries
EVT_CHECKBOX(ID_OVERWRITE_EXISTING, VEILFileSettingsPage::OnOverwriteExistingClick)
EVT_CHECKBOX(ID_CLOSE_WHEN_DONE, VEILFileSettingsPage::OnCloseWhenDoneClick)
EVT_CHECKBOX(ID_DELETE_ENCRYPTION, VEILFileSettingsPage::OnDeleteEncryptionClick)
EVT_CHECKBOX(ID_DELETE_ON_DECRYPTION, VEILFileSettingsPage::OnDeleteOnDecryptionClick)
EVT_TEXT(ID_TIMEOUT, VEILFileSettingsPage::OnTimeoutTextUpdated)
EVT_TEXT(ID_PASSES, VEILFileSettingsPage::OnPassesTextUpdated)
EVT_CHECKBOX(ID_ON_TOP, VEILFileSettingsPage::OnOnTopClick)
EVT_CHOICE(ID_COMPRESSION, VEILFileSettingsPage::OnCompressionSelected)
////@end VEILFilePropertyPage event table entries

END_EVENT_TABLE()

tsmod::IObject* CreateVEILFileSettingsPage()
{
	return dynamic_cast<tsmod::IObject*>(new VEILFileSettingsPage());
}