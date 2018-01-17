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

#include "stdafx.h"
#include "resource.h"
#include "prsht.h"

#define DATA_ENCRYPTION_STANDARD	"The Data Encryption Standard Algorithm, frequently referred to as DES, is widely used within government and financial organizations.  Its use of 56-bit keys provides adequate protection in most situations, although the level of protection provided by DES is not as strong as that available with other algorithms."
#define TRIPLE_DES					"In general terms, the Triple-DES algorithm improves on the standard DES protection by encoding information three times with as many as three different keys.  Its protection of information is strong enough to meet the most demanding requirements.  Triple-DES achieves this level of protection, however, at the cost of performance.  Especially when implemented in software,  Triple-DES is approximately three times slower than standard DES, and 25-40 times slower than TecSec's P-Squared algorithm (depending on file size and mode of Triple-DES used).Although all of the algorithms described here are available to all members, Triple-DES (two key) is the default algorithm - it encodes information three times with two different keys"
//#define PSQUARED					"P-Squared is TecSec's proprietary high performance cryptographic algorithm.  Based on principles developed and studied by the U.S. government for more than 50 years, P-Squared provides cryptographic protection that meets even the most demanding requirements.  Furthermore, P-Squared has been optimized for high performance - encrypting and decrypting files 7-15 times faster than standard DES and 25-40 times faster than Triple-DES (depending on the size of the file and the modes of DES being used).P-Squared is most suited to situations requiring the highest performance while not compromising cryptographic information.  It works well through a wide range of processor speeds and available memory."

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

struct PageDescriptor
{
    HINSTANCE resourceModule;
	int64_t resourceId;
	std::function<int64_t(XP_WINDOW, uint32_t, uint64_t, uint64_t)> func;
	tscrypto::tsCryptoString title;
};

class GeneralSettingsHandler
{
public:
	static std::function<int64_t(XP_WINDOW, uint32_t, uint64_t, uint64_t)> Create(std::shared_ptr<BasicVEILPreferences> prefs)
	{
		std::shared_ptr<GeneralSettingsHandler> _me = std::shared_ptr<GeneralSettingsHandler>(new GeneralSettingsHandler());
		_me->_prefs = prefs;
		return [_me](XP_WINDOW wnd, uint32_t msg, uint64_t wParam, uint64_t lParam)->int64_t{ return _me->GeneralSettingsHandler::GeneralProc((HWND)wnd, msg, (WPARAM)wParam, (LPARAM)lParam); };
	}
	~GeneralSettingsHandler(){}

protected:
	GeneralSettingsHandler() : _bDirty(FALSE), _cbxAlg(nullptr), _cbxHashAlg(nullptr), /*_bCKMweb(FALSE),*/ _Alg(_TS_ALG_ID::TS_ALG_AES_GCM_256),
		_HashAlg(_TS_ALG_ID::TS_ALG_SHA512), _bInitialized(FALSE), _bDisplayMsgDlg(FALSE) {}
	// =============================================================================
	// General Settings dialog
	// =============================================================================

	std::shared_ptr<BasicVEILPreferences> _prefs;
	BOOL _bDirty;
	HWND _cbxAlg;
	HWND _cbxHashAlg;
	//BOOL _bCKMweb;
	TS_ALG_ID _Alg;
	TS_ALG_ID _HashAlg;
	BOOL _bInitialized;
	BOOL _bDisplayMsgDlg;
	tscrypto::tsCryptoString _url;
	tscrypto::tsCryptoString _username;
	tscrypto::tsCryptoString _aidList;

	void DisablePolicyField(HWND hWnd, uint32_t id, JsonConfigLocation location)
	{
		HWND w = GetDlgItem(hWnd, id);

		if (w != nullptr)
		{
			if (location == jc_Policy)
			{
				EnableWindow(w, FALSE);
			}
			else
			{
				EnableWindow(w, TRUE);
			}
		}
	}
	BOOL OnInitDialog(HWND hWnd)
	{
		//
		Initialization(hWnd);

		UpdateData(hWnd, FALSE);

		_bInitialized = TRUE;

		return FALSE;  // return TRUE unless you set the focus to a control
		// EXCEPTION: OCX Property Pages should return FALSE
	}

	void Initialization(HWND hWnd)
	{
		int index;
		_cbxAlg = GetDlgItem(hWnd, IDC_ALG_COMBO);
		_cbxHashAlg = GetDlgItem(hWnd, IDC_HASH_ALG_COMBO);


		_Alg = _prefs->getEncryptionAlgorithm();
		_HashAlg = _prefs->getHashAlgorithm();
		_url = _prefs->getKeyVEILUrl();
		_username = _prefs->getKeyVEILUsername();
		_aidList = _prefs->getAIDList();

		DisablePolicyField(hWnd, IDC_ALG_COMBO, _prefs->EncryptionAlgorithmLocation());
		DisablePolicyField(hWnd, IDC_HASH_ALG_COMBO, _prefs->HashAlgorithmLocation());
		DisablePolicyField(hWnd, IDC_KEYVEIL_URL, _prefs->KeyVEILUrlLocation());
		DisablePolicyField(hWnd, IDC_KEYVEIL_USERNAME, _prefs->KeyVEILUsernameLocation());
		DisablePolicyField(hWnd, IDC_AIDLIST, _prefs->AIDListLocation());

		SendMessage(_cbxAlg, CB_RESETCONTENT, 0, 0);
		for (int i = 0; i < (int)(sizeof(AlgNames) / sizeof(AlgNames[0])); i++)
		{
			index = (int)SendMessage(_cbxAlg, CB_ADDSTRING, 0, (LPARAM)AlgNames[i]);
			SendMessage(_cbxAlg, CB_SETITEMDATA, index, algIds[i]);
		}
		index = FindAlgByID(_Alg);
		if (index != -1)
			SendMessage(_cbxAlg, CB_SETCURSEL, index, 0);

		SendMessage(_cbxHashAlg, CB_RESETCONTENT, 0, 0);
		for (int i = 0; i < (int)(sizeof(HashAlgNames) / sizeof(HashAlgNames[0])); i++)
		{
			index = (int)SendMessage(_cbxHashAlg, CB_ADDSTRING, 0, (LPARAM)HashAlgNames[i]);
			SendMessage(_cbxHashAlg, CB_SETITEMDATA, index, hashAlgIds[i]);
		}
		index = FindHashAlgByID(_HashAlg);
		if (index != -1)
			SendMessage(_cbxHashAlg, CB_SETCURSEL, index, 0);

		SetDlgItemText(hWnd, IDC_KEYVEIL_URL, _url.c_str());
		SetDlgItemText(hWnd, IDC_KEYVEIL_USERNAME, _username.c_str());
		SetDlgItemText(hWnd, IDC_AIDLIST, _aidList.c_str());

		//
		//m_bDisplayMsgDlg = TRUE;


		// TM Setting
		//_bCKMweb = (config.getNodeItemAsNumber("Options", "EnableCkmWeb", 0) != 0);
		// testing

		//        GetDlgItem(IDC_CKMDESKTOP_CHECK)->EnableWindow(!m_filePrefs->getIsStartWithWindowsFromPolicy());
		//        GetDlgItem(IDC_SEC_DEL_PASSES_STATIC)->EnableWindow(!m_psysPrefs->getIsSecureDeleteCountPassFromPolicy());
		//        GetDlgItem(IDC_ALG_COMBO)->EnableWindow(!m_psysPrefs->getIsDefaultEncryptAlgFromPolicy());


		UpdateData(hWnd, FALSE);
	}

	void UpdateData(HWND hWnd, BOOL fromControls)
	{
		int index;

		if (fromControls)
		{
			char buff[512];

			//m_bCKMweb = (SendDlgItemMessage(m_hWnd, IDC_TM_CHECK, BM_GETCHECK, 0, 0) == BST_CHECKED);
			index = (int)SendMessage(_cbxAlg, CB_GETCURSEL, 0, 0);
			if (index != CB_ERR)
			{
				_Alg = (TS_ALG_ID)SendMessage(_cbxAlg, CB_GETITEMDATA, index, 0);
			}
			else
			{
				_Alg = _TS_ALG_ID::TS_ALG_AES_GCM_256;
			}
			index = (int)SendMessage(_cbxHashAlg, CB_GETCURSEL, 0, 0);
			if (index != CB_ERR)
			{
				_HashAlg = (TS_ALG_ID)SendMessage(_cbxHashAlg, CB_GETITEMDATA, index, 0);
			}
			else
			{
				_HashAlg = _TS_ALG_ID::TS_ALG_SHA512;
			}
			buff[0] = 0;
			GetDlgItemText(hWnd, IDC_KEYVEIL_URL, buff, sizeof(buff));
			_url = buff;
			buff[0] = 0;
			GetDlgItemText(hWnd, IDC_KEYVEIL_USERNAME, buff, sizeof(buff));
			_username = buff;
			buff[0] = 0;
			GetDlgItemText(hWnd, IDC_AIDLIST, buff, sizeof(buff));
			_aidList = buff;
		}
		else
		{
			//SendDlgItemMessage(m_hWnd, IDC_TM_CHECK, BM_SETCHECK, (m_bCKMweb) ? BST_CHECKED : BST_UNCHECKED, 0);
			index = FindAlgByID(_Alg);
			SendMessage(_cbxAlg, CB_SETCURSEL, index, 0);
			index = FindHashAlgByID(_HashAlg);
			SendMessage(_cbxHashAlg, CB_SETCURSEL, index, 0);
			SetDlgItemText(hWnd, IDC_KEYVEIL_URL, _url.c_str());
			SetDlgItemText(hWnd, IDC_KEYVEIL_USERNAME, _username.c_str());
			SetDlgItemText(hWnd, IDC_AIDLIST, _aidList.c_str());
		}
	}

	int FindAlgByID(TS_ALG_ID alg)
	{
		int count = (int)SendMessage(_cbxAlg, CB_GETCOUNT, 0, 0);
		int i;

		for (i = 0; i < count; i++)
		{
			if ((TS_ALG_ID)SendMessage(_cbxAlg, CB_GETITEMDATA, i, 0) == alg)
				return i;
		}
		return -1;
	}

	int FindHashAlgByID(TS_ALG_ID alg)
	{
		int count = (int)SendMessage(_cbxHashAlg, CB_GETCOUNT, 0, 0);
		int i;

		for (i = 0; i < count; i++)
		{
			if ((TS_ALG_ID)SendMessage(_cbxHashAlg, CB_GETITEMDATA, i, 0) == alg)
				return i;
		}
		return -1;
	}

	void OnSelchangeAlgCombo(HWND hWnd)
	{
		TS_ALG_ID newAlg;
		int index;

		index = (int)SendMessage(_cbxAlg, CB_GETCURSEL, 0, 0);
		if (index == CB_ERR)
			return;

		newAlg = (TS_ALG_ID)SendMessage(_cbxAlg, CB_GETITEMDATA, index, 0);

		if (newAlg == _Alg)
			return;

		if (_bInitialized)
		{
			if (IDYES == MessageBoxA(hWnd, ("Are you sure you want to change the default algorithm?"), ("VEIL General Settings"), MB_YESNO | MB_ICONINFORMATION))
			{
				_bDisplayMsgDlg = FALSE;
				///
				//m_bInitialized = FALSE;
				///
				SetModified(hWnd);
			}
			else
			{
				index = FindAlgByID(_Alg);
				if (index != CB_ERR)
					SendMessage(_cbxAlg, CB_SETCURSEL, index, 0);
				return;
			}
		}
		_Alg = newAlg;
		UpdateData(hWnd, FALSE);
	}

	void OnSelchangeHashAlgCombo(HWND hWnd)
	{
		TS_ALG_ID newAlg;
		int index;

		index = (int)SendMessage(_cbxHashAlg, CB_GETCURSEL, 0, 0);
		if (index == CB_ERR)
			return;

		newAlg = (TS_ALG_ID)SendMessage(_cbxHashAlg, CB_GETITEMDATA, index, 0);

		if (newAlg == _HashAlg)
			return;

		if (_bInitialized)
		{
			if (IDYES == MessageBoxA(hWnd, ("Are you sure you want to change the default hash algorithm?"), ("CKM Desktop Preferences"), MB_YESNO | MB_ICONINFORMATION))
			{
				_bDisplayMsgDlg = FALSE;
				///
				//m_bInitialized = FALSE;
				///
				SetModified(hWnd);
			}
			else
			{
				index = FindHashAlgByID(_HashAlg);
				if (index != CB_ERR)
					SendMessage(_cbxAlg, CB_SETCURSEL, index, 0);
				return;
			}
		}
		_HashAlg = newAlg;
		UpdateData(hWnd, FALSE);
	}

	BOOL OnApply(HWND hWnd)
	{
		//        HMODULE hCKMWeb = NULL;

		UpdateData(hWnd, TRUE);

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

		UpdateData(hWnd, FALSE);

		SetModified(FALSE);

		return TRUE;
	}

	void SetModified(HWND hWnd, BOOL bChanged = TRUE)
	{
		_bDirty = bChanged;
		if (bChanged)
		{
			PropSheet_Changed(GetParent(hWnd), hWnd);
		}
		else
		{
			PropSheet_UnChanged(GetParent(hWnd), hWnd);
		}
	}

    intptr_t CALLBACK GeneralProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
	{
		BOOL handled = FALSE;

		switch (msg)
		{
		case WM_INITDIALOG:
			OnInitDialog(hWnd);
			break;
		case WM_COMMAND:
			if (wParam == MAKEWPARAM(IDC_ALG_COMBO, CBN_SELCHANGE))
			{
				OnSelchangeAlgCombo(hWnd);
				return TRUE;
			}
			else if (wParam == MAKEWPARAM(IDC_HASH_ALG_COMBO, CBN_SELCHANGE))
			{
				OnSelchangeHashAlgCombo(hWnd);
				return TRUE;
			}
			//else if (wParam == MAKEWPARAM(IDC_ALG_COMBO, CBN_CLOSEUP))
			//{
			//	OnCloseupAlgCombo();
			//	return TRUE;
			//}
			//else if (wParam == MAKEWPARAM(IDC_TM_CHECK, BN_CLICKED))
			//{
			//	OnTmCheck();
			//	return TRUE;
			//}
			break;
		case WM_NOTIFY:
			switch (((NMHDR*)lParam)->code)
			{
			case PSN_HELP:
				{
					std::shared_ptr<IVEILHelpRegistry> help = ::TopServiceLocator()->get_instance<IVEILHelpRegistry>("/WinAPI/HelpRegistry");

					if (!help)
					{
						MessageBoxA(hWnd, ("Help is not available at this time."), ("Status"), MB_OK);
					}
					else
					{
						help->DisplayHelpForWindowId(winid_GeneralSettings, (XP_WINDOW)hWnd);
					}
				}
				break;
			case PSN_APPLY:
				if (!OnApply(hWnd))
				{
					SetWindowLongPtr(hWnd, DWLP_MSGRESULT, PSNRET_INVALID);
				}
				else
				{
					SetWindowLongPtr(hWnd, DWLP_MSGRESULT, PSNRET_NOERROR);
				}
				break;
			case PSN_KILLACTIVE:
				// Validate controls here
				SetWindowLongPtr(hWnd, DWLP_MSGRESULT, FALSE);
				break;
			case PSN_QUERYCANCEL:
				// Return TRUE to not allow CANCEL
				SetWindowLongPtr(hWnd, DWLP_MSGRESULT, FALSE);
				break;
			case PSN_QUERYINITIALFOCUS:
				SetWindowLongPtr(hWnd, DWLP_MSGRESULT, reinterpret_cast<LONG_PTR>(_cbxAlg));
				break;
			case PSN_RESET:
				break;
			case PSN_SETACTIVE:
				// Return 0 to accept the activation or -1 otherwise
				SetWindowLongPtr(hWnd, DWLP_MSGRESULT, 0);
				break;
			case PSN_TRANSLATEACCELERATOR:
				// Requesting normal handling
				SetWindowLongPtr(hWnd, DWLP_MSGRESULT, PSNRET_NOERROR);
				break;
			}
			break;
		}
		return handled;
	}
};

class VEILFileSettingsHandler
{
public:
	static std::function<int64_t(XP_WINDOW, uint32_t, uint64_t, uint64_t)> Create(std::shared_ptr<BasicVEILPreferences> prefs)
	{
		std::shared_ptr<VEILFileSettingsHandler> _me = std::shared_ptr<VEILFileSettingsHandler>(new VEILFileSettingsHandler());
		_me->_prefs = prefs;
		return [_me](XP_WINDOW wnd, uint32_t msg, uint64_t wParam, uint64_t lParam)->int64_t{ return _me->VEILFileSettingsHandler::dlgProc((HWND)wnd, msg, (WPARAM)wParam, (LPARAM)lParam); };
	}
	~VEILFileSettingsHandler(){}

protected:
	VEILFileSettingsHandler() :
		m_bDelAftEnc(FALSE),
		m_bDelAftSig(FALSE),
		m_bDelAftDec(FALSE),
		m_bCertEnc(FALSE),
		m_bCloseAft(FALSE),
		m_bOverWrite(FALSE),
		m_nTimeOut(0),
		m_hWnd(nullptr),
		m_bDirty(FALSE),
		m_nSecureDelete(3),
		m_startOnLogin(FALSE),
		m_bWindowsStart(FALSE),
		m_bAlwaysOnTop(FALSE),
		//m_nPosLeft(0),
		//m_nPosTop(0),
		m_CompType(ct_None)
	{
	}

	// =============================================================================
	// General Settings dialog
	// =============================================================================

	std::shared_ptr<BasicVEILPreferences> _prefs;
	HWND m_hWnd;
	BOOL m_bDirty;
	int m_nSecureDelete;
	BOOL m_startOnLogin;
	BOOL m_bWindowsStart;
	HWND m_cbxCompType;
	//	CkmCompressionType m_Compress;
	int m_CompType;
	BOOL	m_bDelAftEnc;
	BOOL	m_bDelAftSig;
	BOOL	m_bDelAftDec;
	BOOL	m_bCertEnc;
	BOOL	m_bCloseAft;
	BOOL	m_bOverWrite;
	UINT	m_nTimeOut;
	BOOL	m_bAlwaysOnTop;
	//UINT	m_nPosLeft;
	//UINT	m_nPosTop;


	void DisablePolicyField(uint32_t id, JsonConfigLocation location)
	{
		HWND w = GetDlgItem(m_hWnd, id);

		if (w != nullptr)
		{
			if (location == jc_Policy)
			{
				EnableWindow(w, FALSE);
			}
			else
			{
				EnableWindow(w, TRUE);
			}
		}
	}

	void Initialization()
	{
		//PostMessage(m_hWnd, WM_MFC_WORKAROUND_MSG, PREF_CHANGE_NOTIF, 0);

		m_cbxCompType = GetDlgItem(m_hWnd, IDC_COMPTYPE_COMBO);
		SendMessage(m_cbxCompType, CB_RESETCONTENT, 0, 0);
		SendMessage(m_cbxCompType, CB_ADDSTRING, 0, (LPARAM)"None");	// 0
		SendMessage(m_cbxCompType, CB_ADDSTRING, 0, (LPARAM)"zLib");	// 1
		SendMessage(m_cbxCompType, CB_ADDSTRING, 0, (LPARAM)"bZip");	// 2

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
		//m_bCertEnc	 = FALSE;  // TODO:  config.getNodeTextAsBool("Settings/AllowCertEncryption", false);
		m_nSecureDelete = _prefs->getSecureDeletePassCount();
		UINT nTimeout = _prefs->getSessionTimeout();
		m_startOnLogin = FALSE; // TODO: config.getNodeTextAsBool("Settings/StartWithWindows", false);
		m_CompType = _prefs->getCompressionType();
		//m_nPosLeft = _prefs->getWindowPosition().x;
		//m_nPosTop = _prefs->getWindowPosition().y;

		// Set the controls

		m_nTimeOut = nTimeout / 60;

		SendDlgItemMessage(m_hWnd, IDC_TIME_OUT_EDIT, EM_SETLIMITTEXT, 3, 0);
		//SendDlgItemMessage(m_hWnd, IDC_POSLEFT, EM_SETLIMITTEXT, 3, 0);
		//SendDlgItemMessage(m_hWnd, IDC_POSTOP, EM_SETLIMITTEXT, 3, 0);

		// Update the page
		UpdateData(FALSE);

		//        if (GetDlgItem(IDC_OVR_EXIST_CHK))
		//            GetDlgItem(IDC_OVR_EXIST_CHK)->EnableWindow(
		//                            m_psysPrefs->getIsOverwriteExistingFromPolicy () ? FALSE : TRUE);
		//        if (GetDlgItem(IDC_COMP_ENC_CHK))
		//            GetDlgItem(IDC_COMP_ENC_CHK)->EnableWindow(
		//                            m_psysPrefs->getIsCompressEncryptedFromPolicy () ? FALSE : TRUE);
		//        if (GetDlgItem(IDC_ALLOW_CERT_ENC_CHK))
		//            GetDlgItem(IDC_ALLOW_CERT_ENC_CHK)->EnableWindow(
		//                            m_psysPrefs->getIsAllowCertEncryptionFromPolicy () ? FALSE : TRUE);
		//        if (GetDlgItem(IDC_CLOSE_AFT_OPN_CHK))
		//            GetDlgItem(IDC_CLOSE_AFT_OPN_CHK)->EnableWindow(
		//                            m_psysPrefs->getIsCloseAfterOperationFromPolicy () ? FALSE : TRUE);
		//        if (GetDlgItem(IDC_DEL_AFT_ENC_CHK))
		//            GetDlgItem(IDC_DEL_AFT_ENC_CHK)->EnableWindow(
		//                            m_psysPrefs->getIsDeleteAfterEncryptionFromPolicy () ? FALSE : TRUE);
		//        if (GetDlgItem(IDC_DEL_AFT_DECVER_CHK))
		//            GetDlgItem(IDC_DEL_AFT_DECVER_CHK)->EnableWindow(
		//                            m_psysPrefs->getIsDeleteAfterDecryptionFromPolicy () ? FALSE : TRUE);
		//        if (GetDlgItem(IDC_DEL_AFT_SIG_CHK))
		//            GetDlgItem(IDC_DEL_AFT_SIG_CHK)->EnableWindow(
		//                            m_psysPrefs->getIsDeleteAfterSigningFromPolicy () ? FALSE : TRUE);
		//        if (GetDlgItem(IDC_TIME_OUT_EDIT))
		//            GetDlgItem(IDC_TIME_OUT_EDIT)->EnableWindow(
		//                            m_psysPrefs->getIsSessionTimeoutFromPolicy () ? FALSE : TRUE);
		//        GetDlgItem(IDC_SECURE_DELETE)->EnableWindow(!m_psysPrefs->getIsSecureDeleteCountPassFromPolicy());
		//        GetDlgItem(IDC_TM_CHECK)->EnableWindow(!m_psysPrefs->getIsEnableCKMWebFromPolicy());
	}
	void UpdateData(BOOL fromControls)
	{
		if (fromControls)
		{
			char buff[50] = ("");

			m_bOverWrite = (SendDlgItemMessage(m_hWnd, IDC_OVR_EXIST_CHK, BM_GETCHECK, 0, 0) == BST_CHECKED);
			m_bDelAftEnc = (SendDlgItemMessage(m_hWnd, IDC_DEL_AFT_ENC_CHK, BM_GETCHECK, 0, 0) == BST_CHECKED);
			//m_bDelAftSig = (SendDlgItemMessage(m_hWnd, IDC_DEL_AFT_SIG_CHK, BM_GETCHECK, 0, 0) == BST_CHECKED);
			m_bDelAftDec = (SendDlgItemMessage(m_hWnd, IDC_DEL_AFT_DECVER_CHK, BM_GETCHECK, 0, 0) == BST_CHECKED);
			//            m_bCertEnc = (SendDlgItemMessage(m_hWnd, IDC_ALLOW_CERT_ENC_CHK, BM_GETCHECK, 0, 0) == BST_CHECKED);
			m_bCloseAft = (SendDlgItemMessage(m_hWnd, IDC_CLOSE_AFT_OPN_CHK, BM_GETCHECK, 0, 0) == BST_CHECKED);
			SendDlgItemMessage(m_hWnd, IDC_TIME_OUT_EDIT, WM_GETTEXT, sizeof(buff), (LPARAM)buff);
			m_nTimeOut = tsStrToInt(buff);
			buff[0] = 0;
			SendDlgItemMessage(m_hWnd, IDC_SECURE_DELETE, WM_GETTEXT, sizeof(buff), (LPARAM)buff);
			m_nSecureDelete = tsStrToInt(buff);
			//            m_startOnLogin = (SendDlgItemMessage(m_hWnd, IDC_CKMFILE_CHECK, BM_GETCHECK, 0, 0) == BST_CHECKED);
			m_bAlwaysOnTop = (SendDlgItemMessage(m_hWnd, IDC_ALWAYSONTOP, BM_GETCHECK, 0, 0) == BST_CHECKED);
			buff[0] = 0;

			SendDlgItemMessage(m_hWnd, IDC_COMPTYPE_COMBO, WM_GETTEXT, sizeof(buff), (LPARAM)buff);

			if (tsStrCmp(buff, ("zLib")) == 0)
				m_CompType = ct_zLib;
			else if (tsStrCmp(buff, ("bZip")) == 0)
				m_CompType = ct_BZ2;
			else
				m_CompType = ct_None;

			//SendDlgItemMessage(m_hWnd, IDC_POSLEFT, WM_GETTEXT, sizeof(buff), (LPARAM)buff);
			//m_nPosLeft = tsStrToInt(buff);
			//buff[0] = 0;
			//SendDlgItemMessage(m_hWnd, IDC_POSTOP, WM_GETTEXT, sizeof(buff), (LPARAM)buff);
			//m_nPosTop = tsStrToInt(buff);
		}
		else
		{
			char buff[50];

			DisablePolicyField(IDC_OVR_EXIST_CHK, _prefs->OverwriteExistingLocation());
			SendDlgItemMessage(m_hWnd, IDC_OVR_EXIST_CHK, BM_SETCHECK, (m_bOverWrite ? BST_CHECKED : BST_UNCHECKED), 0);
			
			DisablePolicyField(IDC_DEL_AFT_ENC_CHK, _prefs->DeleteAfterEncryptionLocation());
			SendDlgItemMessage(m_hWnd, IDC_DEL_AFT_ENC_CHK, BM_SETCHECK, (m_bDelAftEnc ? BST_CHECKED : BST_UNCHECKED), 0);
			
			//DisablePolicyField(IDC_DEL_AFT_SIG_CHK, _prefs->DeleteAfterSignatureLocation());
			//SendDlgItemMessage(m_hWnd, IDC_DEL_AFT_SIG_CHK, BM_SETCHECK, (m_bDelAftSig ? BST_CHECKED : BST_UNCHECKED), 0);
			
			DisablePolicyField(IDC_DEL_AFT_DECVER_CHK, _prefs->DeleteAfterDecryptionLocation());
			SendDlgItemMessage(m_hWnd, IDC_DEL_AFT_DECVER_CHK, BM_SETCHECK, (m_bDelAftDec ? BST_CHECKED : BST_UNCHECKED), 0);
			
			//DisablePolicyField(IDC_ALLOW_CERT_ENC_CHK, _prefs->xxxLocation());
			//            SendDlgItemMessage(m_hWnd, IDC_ALLOW_CERT_ENC_CHK, BM_SETCHECK, (m_bCertEnc ? BST_CHECKED : BST_UNCHECKED), 0);
			
			DisablePolicyField(IDC_CLOSE_AFT_OPN_CHK, _prefs->CloseAfterOperationLocation());
			SendDlgItemMessage(m_hWnd, IDC_CLOSE_AFT_OPN_CHK, BM_SETCHECK, (m_bCloseAft ? BST_CHECKED : BST_UNCHECKED), 0);
			tsSnPrintf(buff, sizeof(buff) / sizeof(buff[0]), ("%d"), m_nTimeOut);
			
			DisablePolicyField(IDC_TIME_OUT_EDIT, _prefs->SessionTimeoutLocation());
			SendDlgItemMessage(m_hWnd, IDC_TIME_OUT_EDIT, WM_SETTEXT, 0, (LPARAM)buff);
			
			tsSnPrintf(buff, sizeof(buff) / sizeof(buff[0]), ("%d"), m_nSecureDelete);
			DisablePolicyField(IDC_SECURE_DELETE, _prefs->SecureDeletePassCountLocation());
			SendDlgItemMessage(m_hWnd, IDC_SECURE_DELETE, WM_SETTEXT, 0, (LPARAM)buff);
			
			// DisablePolicyField(IDC_CKMFILE_CHECK, _prefs->xxxLocation());
			//            SendDlgItemMessage(m_hWnd, IDC_CKMFILE_CHECK, BM_SETCHECK, (m_startOnLogin) ? BST_CHECKED : BST_UNCHECKED, 0);

			DisablePolicyField(IDC_ALWAYSONTOP, _prefs->AlwaysOnTopLocation());
			SendDlgItemMessage(m_hWnd, IDC_ALWAYSONTOP, BM_SETCHECK, (m_bAlwaysOnTop) ? BST_CHECKED : BST_UNCHECKED, 0);
			
			//tsSnPrintf(buff, sizeof(buff) / sizeof(buff[0]), ("%d"), m_nPosLeft);
			////DisablePolicyField(IDC_POSLEFT, _prefs->());
			//SendDlgItemMessage(m_hWnd, IDC_POSLEFT, WM_SETTEXT, 0, (LPARAM)buff);
			//
			//tsSnPrintf(buff, sizeof(buff) / sizeof(buff[0]), ("%d"), m_nPosTop);
			////DisablePolicyField(IDC_POSTOP, _prefs->());
			//SendDlgItemMessage(m_hWnd, IDC_POSTOP, WM_SETTEXT, 0, (LPARAM)buff);

			DisablePolicyField(IDC_COMPTYPE_COMBO, _prefs->CompressionTypeLocation());
			SendDlgItemMessage(m_hWnd, IDC_COMPTYPE_COMBO, CB_SETCURSEL, m_CompType, 0);
		}
	}

	BOOL OnInitDialog()
	{
		// Initialize the controls
		Initialization();
		m_bWindowsStart = FALSE;

		return TRUE;  // return TRUE unless you set the focus to a control
		// EXCEPTION: OCX Property Pages should return FALSE
	}

	void SetModified(BOOL bChanged = TRUE)
	{
		m_bDirty = bChanged;
		if (m_bDirty)
		{
			PropSheet_Changed(GetParent(m_hWnd), m_hWnd);
		}
		else
		{
			PropSheet_UnChanged(GetParent(m_hWnd), m_hWnd);
		}
	}

	virtual BOOL OnApply()
	{
		// Get the values from the dialog
		UpdateData(TRUE);
		// Get the values of the controls

		UINT nTimeout = m_nTimeOut * 60;
//		POINT winPt = { (int32_t)m_nPosLeft, (int32_t)m_nPosTop };

		_prefs->setAlwaysOnTop(m_bAlwaysOnTop ? true : false);
		_prefs->setDeleteAfterEncryption(m_bDelAftEnc ? true : false);
		_prefs->setDeleteAfterSigning(m_bDelAftSig ? true : false);
		_prefs->setDeleteAfterDecryption(m_bDelAftDec ? true : false);
		_prefs->setOverwriteExisting(m_bOverWrite ? true : false);
		_prefs->setCloseAfterOperation(m_bCloseAft ? true : false);
		_prefs->setSecureDeletePassCount(m_nSecureDelete);
		_prefs->setSessionTimeout(nTimeout);
		_prefs->setCompressionType((CompressionType)m_CompType);
		//_prefs->setWindowPosition(winPt);

		//        config.setNodeTextAsBool("Settings/AllowCertEncryption", (m_bCertEnc ? true : false));
		//        config.setNodeTextAsNumber("Settings/StartWithWindows", m_startOnLogin);

		_prefs->saveConfigurationChanges();

		//if (m_bWindowsStart)
		//{
		//	if (m_startOnLogin)
		//	{
		//		StartWindowWindows();
		//	}
		//	else
		//	{
		//		DontStartWindowWindows();
		//	}
		//}

		SetModified(FALSE);
		return TRUE;
	}

	BOOL ValidateTimeOutEdit()
	{
		char buff[50] = ("");
		unsigned int value;
		HWND pEdit;
		int numChars = GetDlgItemTextA(m_hWnd, IDC_TIME_OUT_EDIT, buff, sizeof(buff));

		if (numChars == 0)
		{
			MessageBoxA(m_hWnd, ("Please enter a number between 0 and 999."),
				("VEIL Settings Timeout Preferences"), MB_OK | MB_ICONWARNING);

			pEdit = GetDlgItem(m_hWnd, IDC_TIME_OUT_EDIT);
			SetFocus(pEdit);
			SendMessage(pEdit, EM_SETSEL, 0, -1);
			return FALSE;
		}

		value = tsStrToInt(buff);
		if (value > 999)
		{
			MessageBoxA(m_hWnd, ("Please enter a number between 0 and 999."),
				("VEIL Settings Timeout Preferences"), MB_OK | MB_ICONWARNING);

			pEdit = GetDlgItem(m_hWnd, IDC_TIME_OUT_EDIT);
			SetFocus(pEdit);
			SendMessage(pEdit, EM_SETSEL, 0, -1);
			return FALSE;
		}

		return TRUE;
	}


	// TODO finish implmentation
	//BOOL ValidatePositionEdit()
	//{
	//	char buff[50] = ("");
	//	unsigned int value;
	//	HWND pEdit;
	//	// LEFT
	//	int numChars = GetDlgItemTextA(m_hWnd, IDC_POSLEFT, buff, sizeof(buff));

	//	if (numChars == 0)
	//	{
	//		MessageBoxA(m_hWnd, ("Please enter a number between 0 and 1200."),
	//			("VEIL Settings Left Position Preferences"), MB_OK | MB_ICONWARNING);

	//		pEdit = GetDlgItem(m_hWnd, IDC_POSLEFT);
	//		SetFocus(pEdit);
	//		SendMessage(pEdit, EM_SETSEL, 0, -1);
	//		return FALSE;
	//	}

	//	value = tsStrToInt(buff);

	//	if (value > 1200)
	//	{
	//		MessageBoxA(m_hWnd, ("Please enter a number from 0 and 1200."),
	//			("VEIL Settings Left Position Preferences"), MB_OK | MB_ICONWARNING);

	//		pEdit = GetDlgItem(m_hWnd, IDC_POSLEFT);
	//		SetFocus(pEdit);
	//		SendMessage(pEdit, EM_SETSEL, 0, -1);
	//		return FALSE;
	//	}
	//	// TOP
	//	numChars = GetDlgItemTextA(m_hWnd, IDC_POSTOP, buff, sizeof(buff));

	//	if (numChars == 0)
	//	{
	//		MessageBoxA(m_hWnd, ("Please enter a number between 0 and 780."),
	//			("VEIL Settings Top Position Preferences"), MB_OK | MB_ICONWARNING);

	//		pEdit = GetDlgItem(m_hWnd, IDC_POSTOP);
	//		SetFocus(pEdit);
	//		SendMessage(pEdit, EM_SETSEL, 0, -1);
	//		return FALSE;
	//	}

	//	value = tsStrToInt(buff);

	//	if (value > 780)
	//	{
	//		MessageBoxA(m_hWnd, ("Please enter a number from 0 and 780."),
	//			("VEIL Settings Top Position Preferences"), MB_OK | MB_ICONWARNING);

	//		pEdit = GetDlgItem(m_hWnd, IDC_POSTOP);
	//		SetFocus(pEdit);
	//		SendMessage(pEdit, EM_SETSEL, 0, -1);
	//		return FALSE;
	//	}

	//	return TRUE;
	//}

	void OnCloseAftOpnChk()
	{
		SetModified();
	}

	void OnCompEncChk()
	{
		SetModified();
	}

	void OnDelAftDecVerChk()
	{
		if (SendDlgItemMessage(m_hWnd, IDC_DEL_AFT_DECVER_CHK, BM_GETCHECK, 0, 0) == BST_CHECKED)
		{
			if (IDYES == MessageBoxA
				(m_hWnd, "Selecting this option will securely delete your original "
				"file following Decryption.  "
				//                             "file following Decryption or Verification operations.  "
				"You will not be able to recover the original.  "
				"Do you wish to continue?",
				"CKM Desktop Preferences", MB_YESNO | MB_ICONWARNING))
			{
				SetModified();
			}
			else
			{
				SendDlgItemMessage(m_hWnd, IDC_DEL_AFT_DECVER_CHK, BM_SETCHECK, BST_UNCHECKED, 0);
			}
		}
		else
		{
			SetModified();
		}
	}

	void OnDelAftEncChk()
	{
		if (SendDlgItemMessage(m_hWnd, IDC_DEL_AFT_ENC_CHK, BM_GETCHECK, 0, 0) == BST_CHECKED)
		{
			if (IDYES == MessageBoxA
				(m_hWnd, "Selecting this option will securely delete your original "
				"file following Encryption operations.  "
				"You will not be able to recover the original.  "
				"Do you wish to continue?",
				"CKM Desktop Preferences", MB_YESNO | MB_ICONWARNING))
			{
				SetModified();
			}
			else
			{
				SendDlgItemMessage(m_hWnd, IDC_DEL_AFT_ENC_CHK, BM_SETCHECK, BST_UNCHECKED, 0);
			}
		}
		else
		{
			SetModified();
		}
	}

	void OnDelAftSigChk()
	{
		//if( SendDlgItemMessage(m_hWnd, IDC_DEL_AFT_SIG_CHK, BM_GETCHECK, 0, 0) == BST_CHECKED )
		//{
		//    if( IDYES == MessageBoxA
		//                    (m_hWnd, "Selecting this option will securely delete your original "
		//                     "file following Signing operations.  "
		//                     "You will not be able to recover the original.  "
		//                     "Do you wish to continue?",
		//                     "CKM Desktop Preferences", MB_YESNO | MB_ICONWARNING) )
		//    {
		//        SetModified();
		//    }
		//    else
		//    {
		//         //Uncheck the box
		//        SendDlgItemMessageA(m_hWnd, IDC_DEL_AFT_SIG_CHK, BM_SETCHECK, BST_UNCHECKED, 0);
		//    }
		//}
		//else
		//{
		//    SetModified();
		//}
	}

	void OnChangeTimeOutEdit()
	{
		SetModified();
	}

	void OnOvrExistChk()
	{
		SetModified();
	}
	void OnChangeSecureDelete()
	{
		SetModified();
	}

	void OnAlwaysOnTopChk()
	{
		SetModified();
	}

	void OnPosLeftEdit()
	{
		SetModified();
	}

	void OnPosTopEdit()
	{
		SetModified();
	}

	void OnSelchangeCompTypeCombo()
	{
		int index;

		index = (int)SendMessage(m_cbxCompType, CB_GETCURSEL, 0, 0);

		if (index == CB_ERR)
			return;

		//        SendMessage(m_cbxCompType, CB_SETCURSEL, index, 0);
		SetModified();

		m_CompType = index;
		UpdateData(FALSE);
	}

    intptr_t CALLBACK dlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
	{
		BOOL handled = FALSE;

		switch (msg)
		{
		case WM_INITDIALOG:
			m_hWnd = hWnd;
			OnInitDialog();
			break;
		case WM_COMMAND:
			//if ( wParam == MAKEWPARAM(IDC_ALLOW_CERT_ENC_CHK, BN_CLICKED) )
			//{
			//    This->OnAllowCertEncChk();
			//    return TRUE;
			//} else 
			if (wParam == MAKEWPARAM(IDC_CLOSE_AFT_OPN_CHK, BN_CLICKED))
			{
				OnCloseAftOpnChk();
				return TRUE;
			}
			else if (wParam == MAKEWPARAM(IDC_DEL_AFT_DECVER_CHK, BN_CLICKED))
			{
				OnDelAftDecVerChk();
				return TRUE;
			}
			else if (wParam == MAKEWPARAM(IDC_DEL_AFT_ENC_CHK, BN_CLICKED))
			{
				OnDelAftEncChk();
				return TRUE;
			}
			//else if (wParam == MAKEWPARAM(IDC_DEL_AFT_SIG_CHK, BN_CLICKED))
			//{
			//	OnDelAftSigChk();
			//	return TRUE;
			//}
			else if (wParam == MAKEWPARAM(IDC_OVR_EXIST_CHK, BN_CLICKED))
			{
				OnOvrExistChk();
				return TRUE;
			}
			else if (wParam == MAKEWPARAM(IDC_TIME_OUT_EDIT, EN_CHANGE))
			{
				OnChangeTimeOutEdit();
				return TRUE;
			}
			else if (wParam == MAKEWPARAM(IDC_SECURE_DELETE, EN_CHANGE))
			{
				OnChangeSecureDelete();
				return TRUE;
			}
			//else if ( wParam == MAKEWPARAM(IDC_CKMFILE_CHECK, BN_CLICKED) )
			//{
			//    This->OnCkmdesktopCheck();
			//    return TRUE;
			//}
			else if (wParam == MAKEWPARAM(IDC_ALWAYSONTOP, BN_CLICKED))
			{
				OnAlwaysOnTopChk();
				return TRUE;
			}
			//else if (wParam == MAKEWPARAM(IDC_POSLEFT, EN_CHANGE))
			//{
			//	OnPosLeftEdit();
			//	return TRUE;
			//}
			//else if (wParam == MAKEWPARAM(IDC_POSTOP, EN_CHANGE))
			//{
			//	OnPosTopEdit();
			//	return TRUE;
			//}
			else if (wParam == MAKEWPARAM(IDC_COMPTYPE_COMBO, CBN_SELCHANGE))
			{
				OnSelchangeCompTypeCombo();
				return TRUE;
			}
			break;
		case WM_NOTIFY:
			switch (((NMHDR*)lParam)->code)
			{
			case PSN_HELP:
				{
					std::shared_ptr<IVEILHelpRegistry> help = ::TopServiceLocator()->get_instance<IVEILHelpRegistry>("/WinAPI/HelpRegistry");

					if (!help)
					{
						MessageBoxA(hWnd, ("Help is not available at this time."), ("Status"), MB_OK);
					}
					else
					{
						help->DisplayHelpForWindowId(winid_FileSettings, (XP_WINDOW)hWnd);
					}
				}
				break;
			case PSN_APPLY:
				if (!OnApply())
				{
					SetWindowLongPtr(hWnd, DWLP_MSGRESULT, PSNRET_INVALID);
				}
				else
				{
					SetWindowLongPtr(hWnd, DWLP_MSGRESULT, PSNRET_NOERROR);
				}
				break;
			case PSN_KILLACTIVE:
				// Validate controls here
				if (!ValidateTimeOutEdit() /*|| !ValidatePositionEdit()*/)
					SetWindowLongPtr(hWnd, DWLP_MSGRESULT, TRUE);
				else
					SetWindowLongPtr(hWnd, DWLP_MSGRESULT, FALSE);
				break;
			case PSN_QUERYCANCEL:
				// Return TRUE to not allow CANCEL
				SetWindowLongPtr(hWnd, DWLP_MSGRESULT, FALSE);
				break;
			case PSN_QUERYINITIALFOCUS:
				SetWindowLongPtr(hWnd, DWLP_MSGRESULT, 0);
				break;
			case PSN_RESET:
				break;
			case PSN_SETACTIVE:
				// Return 0 to accept the activation or -1 otherwise
				SetWindowLongPtr(hWnd, DWLP_MSGRESULT, 0);
				break;
			case PSN_TRANSLATEACCELERATOR:
				// Requesting normal handling
				SetWindowLongPtr(hWnd, DWLP_MSGRESULT, PSNRET_NOERROR);
				break;
			}
			break;
		}
		return handled;
	}

};

class VEILPropertySheet : public IVEILPropertySheet, public tsmod::IObject
{
public:
	VEILPropertySheet() : _parent(nullptr), m_psp(nullptr)
	{
		_prefs = BasicVEILPreferences::Create();
		if (!!_prefs)
			_prefs->loadValues();
	}
	virtual ~VEILPropertySheet()
	{
		if (m_psp != nullptr)
			delete[] m_psp;
		m_psp = nullptr;
	}

	// IVEILUIBase
	virtual void Destroy()
	{
		_parent = XP_WINDOW_INVALID;
		if (m_psp != nullptr)
			delete[] m_psp;
		m_psp = nullptr;
	}
	virtual int  DisplayModal()
	{
		if (pages.size() == 0)
			return false;

		m_psp = new PROPSHEETPAGE[pages.size()];
		if (m_psp == nullptr)
			return false;

		memset(m_psp, 0, sizeof(PROPSHEETPAGE) * pages.size());
		memset(&_PropSheet, 0, sizeof(_PropSheet));

		_PropSheet.dwSize = sizeof(PROPSHEETHEADER);
		_PropSheet.dwFlags = PSH_PROPSHEETPAGE | /*PSH_USECALLBACK |*/ PSH_HASHELP;
		_PropSheet.hInstance = (HINSTANCE)hDllInstance;
		_PropSheet.pszCaption = (char*) "VEIL Settings";
		_PropSheet.nPages = (UINT)pages.size();
		_PropSheet.nStartPage = 0;
		_PropSheet.ppsp = (LPCPROPSHEETPAGE)m_psp;
		//_PropSheet.pfnCallback = (PFNPROPSHEETCALLBACK)SheetProc;
		_PropSheet.hwndParent = (HWND)_parent;

		for (size_t i = 0; i < pages.size(); i++)
		{
			m_psp[i].dwSize = sizeof(PROPSHEETPAGE);
			m_psp[i].dwFlags = PSP_USETITLE | PSP_HASHELP;
			m_psp[i].hInstance = pages[i].resourceModule;
			m_psp[i].pszTemplate = (const char*)pages[i].resourceId;
			m_psp[i].pszTitle = pages[i].title.c_str();
			m_psp[i].pfnDlgProc = (DLGPROC)PageProc;
			m_psp[i].lParam = (LPARAM)&pages[i].func;
		}


		PropertySheet(&_PropSheet);
		return true;
	}
	virtual int  DisplayModal(XP_WINDOW wnd)
	{
		_parent = wnd;
		return DisplayModal();
	}

	// IFavoriteName
	virtual bool Start(XP_WINDOW parent)
	{
		Destroy();

		_parent = parent;

		return true;
	}
	virtual void AddStandardPage(StandardPropPage pageType)
	{
		PageDescriptor page;

		if (pages.size() >= 10)
			return;

		page.resourceModule = hDllInstance;

		switch (pageType)
		{
		case IVEILPropertySheet::VEILFileSettings:
			page.resourceId = IDD_VEIL_FILE_SETTINGS_PAGE;
			page.title = "FileVEIL";
			page.func = VEILFileSettingsHandler::Create(_prefs);
			pages.push_back(page);
			break;
		case IVEILPropertySheet::GeneralSettings:
			page.resourceId = IDD_VEIL_DEFAULT_PAGE;
			page.title = "General";
			page.func = GeneralSettingsHandler::Create(_prefs);
			pages.push_back(page);
			break;
		}
	}
	virtual void AddCustomPage(HINSTANCE resourceModule, int64_t resourceId, std::function<int64_t(XP_WINDOW, uint32_t, uint64_t, uint64_t)> func, const tscrypto::tsCryptoString& title)
	{
		PageDescriptor page;

		if (pages.size() >= 10)
			return;

		page.resourceModule = resourceModule;
		page.resourceId = resourceId;
		page.func = func;
		page.title = title;
		pages.push_back(page);
	}
	virtual std::shared_ptr<BasicVEILPreferences> BasicPreferences()
	{
		return _prefs;
	}
protected:
	XP_WINDOW  _parent;
	PROPSHEETHEADER	_PropSheet;
	PROPSHEETPAGE *m_psp;
	std::vector<PageDescriptor> pages;
	std::shared_ptr<BasicVEILPreferences> _prefs;

	// callback function for property sheet
	static LRESULT CALLBACK SheetProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
	{
		//ShowWindow(GetDlgItem(hDlg, IDOK), SW_HIDE);
		//ShowWindow(GetDlgItem(hDlg, IDCANCEL), SW_HIDE);
		//ShowWindow(GetDlgItem(hDlg, ID_APPLY_NOW), SW_HIDE);

		//PropSheet_GetTabControl(hDlg) \
				 //       (HWND)SNDMSG(hDlg, PSM_GETTABCONTROL, 0, 0)


		// set a bold font to the tabs
		//LOGFONT m_lfont;

		//m_lfont.lfHeight = 8;
		//m_lfont.lfWeight = FW_NORMAL;
		//m_lfont.lfPitchAndFamily = DEFAULT_PITCH | FF_DONTCARE;
		//tsStrCpy(m_lfont.lfFaceName, _T("Arial"));
		//HWND hTabCtrl = PropSheet_GetTabControl(hDlg);
		//		SendMessage(hTabCtrl, WM_SETFONT, (WPARAM)&m_lfont, 0);

		switch (message)
		{
		case WM_INITDIALOG:
			return TRUE;

		case WM_COMMAND:
			if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
			{
				EndDialog(hDlg, LOWORD(wParam));
				return TRUE;
			}
			break;
		}
		return FALSE;
	}

	// Top level wrapper callback for the pages.  Redirects the call to the stored function.
	static LRESULT CALLBACK PageProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
	{
		std::function<int64_t(XP_WINDOW, uint32_t, uint64_t, uint64_t)> *func = (std::function<int64_t(XP_WINDOW, uint32_t, uint64_t, uint64_t)> *)GetWindowLongPtr(hWnd, DWLP_USER);
		PROPSHEETPAGE *page;

		switch (msg)
		{
		case WM_INITDIALOG:
			page = reinterpret_cast<PROPSHEETPAGE*>(lParam);
			func = reinterpret_cast<std::function<int64_t(XP_WINDOW, uint32_t, uint64_t, uint64_t)> *>(page->lParam);
			SetWindowLongPtr(hWnd, DWLP_USER, page->lParam);
			break;
		}
		if (!!func)
			return (intptr_t)((*func)((XP_WINDOW)hWnd, msg, wParam, lParam));
		return FALSE;
	}

#pragma region General Settings
#pragma endregion


#pragma region VEILFile settings
	// =============================================================================
	// VEILfile Settings
	// =============================================================================




#pragma endregion
};

tsmod::IObject* CreateVEILPropertySheet()
{
	return dynamic_cast<tsmod::IObject*>(new VEILPropertySheet());
}


