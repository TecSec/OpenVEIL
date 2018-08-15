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
#include <commctrl.h>
#include "richedit.h"
#include "resource.h"

#define WM_POSTINIT            (WM_USER + 1001)
//#define WM_CRYPTOGROUPLOGIN    (WM_USER + 1002)

#define AS_SEL_DOM_STR ("<Select a Token...>")
#define SAVE_FAVORITE_LINE ("<Save a new favorite>")

#define EMPTY_SLOT_PREFIX "<Slot "
#define EMPTY_SLOT_SUFFIX " Empty>"

class AudienceSelector : public IAudienceSelector, public tsmod::IObject
{
public:
	AudienceSelector(bool createFavorites) : _NeverShowPKI(true), _AlwaysShowPKI(false), _RequireEncCert(false), _CreateFavorites(createFavorites),
		_PKIHidden(false), _hDlg(nullptr), _GroupCtrl(nullptr), _RichCertList(nullptr), _FavoriteCombo(nullptr), /*_CryptoGroupCombo(nullptr),*/ _TokenCombo(nullptr),
		_CurFavIndex(0), _LastTokenSelection(0), _initialized(false), _cookie(0), _ActiveCryptoGroup(nullptr)
	{
	}
	virtual ~AudienceSelector()
	{
		Destroy();
	}
	virtual void OnConstructionFinished() override
	{
		if (!::TopServiceLocator()->CanCreate("/CmsHeader"))
		{
			InitializeCmsHeader();
		}
		_header = ::TopServiceLocator()->get_instance<ICmsHeader>("/CmsHeader");
	}

	// IVEILUIBase
	virtual void Destroy() override
	{
		try
		{
			_parent = XP_WINDOW_INVALID;
			_session.reset();
			_profile.reset();
			_ActiveCryptoGroup = nullptr;
			if (!!_connector && _cookie != 0)
			{
				_connector->RemoveKeyVEILChangeCallback(_cookie);
				_cookie = 0;
			}
			_connector.reset();
			_header.reset();
			_NeverShowPKI = true;
			_AlwaysShowPKI = false;
			_RequireEncCert = false;
			_CreateFavorites = false;
			_PKIHidden = false;
			_AppName.clear();
			_hDlg = nullptr;
			_GroupCtrl = nullptr;
			_RichCertList = nullptr;
			_FavoriteCombo = nullptr;
			//_CryptoGroupCombo = nullptr;
			_TokenCombo = nullptr;
			_CurFavIndex = 0;
			_LastTokenSelection = 0;
			_initialized = false;
		}
		catch (...)
		{
		}
	}
	virtual int  DisplayModal() override
	{
		try
		{
			if (_parent == XP_WINDOW_INVALID)
				_parent = (XP_WINDOW)GetActiveWindow();
			return (int)DialogBoxParamA((HINSTANCE)hDllInstance, MAKEINTRESOURCEA(IDD_AUDIENCE_SELECTOR), (HWND)_parent, &AudienceSelector::AudienceSelectorProc, (LPARAM)this);
		}
		catch (...)
		{
			return IDCANCEL;
		}
	}
	virtual int  DisplayModal(XP_WINDOW wnd) override
	{
		_parent = wnd;
		return DisplayModal();
	}

	// IAudienceSelector
	virtual std::shared_ptr<IKeyVEILConnector> Connector() override
	{
		return _connector;
	}
	virtual void Connector(std::shared_ptr<IKeyVEILConnector> setTo) override
	{
		_connector.reset();
		_session.reset();
		_profile.reset();
		_ActiveCryptoGroup = nullptr;
		_connector = setTo;
	}
	virtual std::shared_ptr<IKeyVEILSession> Session() override
	{
		return _session;
	}
	bool HasSession() const
	{
		return !!_session;
	}
	virtual void Session(std::shared_ptr<IKeyVEILSession> setTo) override
	{
		_session.reset();
		_profile.reset();
		_ActiveCryptoGroup = nullptr;
		_session = setTo;

	}
	std::shared_ptr<Asn1::CTS::_POD_Profile> GetProfile()
	{
		if (!HasSession())
			return nullptr;
		if (!!_profile)
			return _profile;
		if (Session()->IsLoggedIn())
			_profile = Session()->GetProfile();
		return _profile;
	}
	bool HasProfile()
	{
		return !!GetProfile();
	}
	virtual tscrypto::tsCryptoData HeaderData() override
	{
		return _header->ToBytes();
	}
	virtual void HeaderData(const tscrypto::tsCryptoData& setTo) override
	{
		if (!_header->FromBytes(setTo))
			_header->Clear();
	}
	virtual std::shared_ptr<ICmsHeader> Header() override
	{
		return _header;
	}
	virtual void Header(std::shared_ptr<ICmsHeader> setTo) override
	{
		_header.reset();
		_header = setTo;
	}
	virtual bool Start(std::shared_ptr<IKeyVEILConnector> connector, XP_WINDOW parent, const tscrypto::tsCryptoString& appName)
	{
		INITCOMMONCONTROLSEX icc;

		try
		{
			icc.dwSize = sizeof(icc);
			icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES | ICC_TAB_CLASSES | ICC_WIN95_CLASSES;
			InitCommonControlsEx(&icc);

			if (!!connector)
			{
				Connector(connector);
				_cookie = _connector->AddKeyVEILChangeCallback([this](JSONObject& eventData) {
					if (eventData.AsString("type") == "Token")
					{
						if (eventData.AsString("event") == "add")
						{
							OnTokenAdd(eventData.AsString("serial").HexToData());
						}
						else if (eventData.AsString("event") == "delete")
						{
							OnTokenRemove(eventData.AsString("serial").HexToData());
						}
						else
						{
							OnTokenDataChange(eventData.AsString("serial").HexToData());
						}
					}
					else if (eventData.AsString("type") == "Favorite")
					{
						InitFavorites();
						// OnFavoriteAdd
					}
				});
			}
			_parent = parent;
			_AppName = appName;

			if (!_connector)
				return false;

			return true;
		}
		catch (...)
		{
			return false;
		}
	}

protected:
	XP_WINDOW									_parent;
	std::shared_ptr<IKeyVEILSession>			_session;
	std::shared_ptr<IKeyVEILConnector>			_connector;
	std::shared_ptr<ICmsHeader>					_header;
	bool										_NeverShowPKI;
	bool										_AlwaysShowPKI;
	bool										_RequireEncCert;
	bool										_CreateFavorites;
	bool										_PKIHidden;
	tscrypto::tsCryptoString					_AppName;
	HWND  										_hDlg;
	HWND										_GroupCtrl;
	HWND										_RichCertList;
	HWND										_FavoriteCombo;
	//	HWND									    _CryptoGroupCombo;
	HWND										_TokenCombo;
	int											_CurFavIndex;
	Asn1::CTS::_POD_CryptoGroup*				_ActiveCryptoGroup;
	int											_LastTokenSelection;
	std::shared_ptr<IFavorite>					_favorite;
	bool										_initialized;
	std::vector<tscrypto::tsCryptoData>			_tokenSerialNumbers;
	std::vector<GUID>							_guidMap;
	size_t										_cookie;
	std::shared_ptr<Asn1::CTS::_POD_Profile>	_profile;

	static intptr_t CALLBACK	AudienceSelectorProc(HWND _hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
	{
		AudienceSelector *params = (AudienceSelector*)GetWindowLongPtr(_hDlg, DWLP_USER);

		switch (msg)
		{
		case WM_INITDIALOG:
			SetWindowLongPtr(_hDlg, DWLP_USER, lParam);
			params = (AudienceSelector*)lParam;

			EnableWindow(GetDlgItem(_hDlg, IDOK), FALSE);

			{
				HWINSTA station = GetProcessWindowStation();
				DWORD count;
				char buff[MAX_PATH + 1] = { 0, };

				memset(buff, 0, sizeof(buff));
				GetUserObjectInformationA(station, UOI_NAME, buff, sizeof(buff), &count);
				if (strstr(buff, "WinSta0") == NULL)
				{
					EndDialog(_hDlg, IDCANCEL);
				}
			}
			params->_hDlg = _hDlg;
			return params->OnInitDialog();

		case WM_DESTROY:
			params->OnWmDestroy();
			break;

		case WM_COMMAND:
			if (HIWORD(wParam) == BN_CLICKED)
			{
				switch (LOWORD(wParam))
				{
				case IDOK:
					return params->OnOK();
				case IDCANCEL:
					EndDialog(_hDlg, IDCANCEL);
					break;
				case IDC_TOKEN_LOGIN:
					params->LoginTokenPressed();
					break;
				case IDHELP:
					return params->OnHelp();
				case IDC_USE_MY_CERT:
					return params->OnUseMyCert();
				case IDC_GROUPADD:
					return params->OnGroupAdd();
				case IDC_GROUPDELETE:
					return params->OnGroupDelete();
				case IDC_CERTDELETE:
					return params->OnCertDelete();
				case IDC_GROUPEDIT:
					return params->OnGroupEdit();
				case IDC_CREATE_FAVORITE:
					return params->OnCreateFavorite();
				case IDC_DELETE_FAVORITE:
					return params->OnDeleteFavorite();
				case IDC_PEOPLE:
					return params->OnPeople();
				case IDC_PASSWORD:
					return params->OnPassword();
				}
			}
			else if (HIWORD(wParam) == CBN_DROPDOWN)
			{
				//switch (LOWORD(wParam))
				//{
				//case IDC_CRYPTOGROUPCOMBO:
				//	return  params->OnCryptoGroupBoxPress();
				//}
			}
			else if (HIWORD(wParam) == CBN_SELENDOK)
			{
				switch (LOWORD(wParam))
				{
					//case IDC_CRYPTOGROUPCOMBO:
					//	return params->CryptoGroupKeyPressLogin();
				case IDC_FAVORITECOMBO:
					return params->OnChangeFavorite();
				}
			}
			else if (HIWORD(wParam) == CBN_SELCHANGE)
			{
				switch (LOWORD(wParam))
				{
				case IDC_TOKENCOMBO:
					return params->OnChangeTokenByControl();
					//case IDC_CRYPTOGROUPCOMBO:
					//	return params->OnChangeCryptoGroup();
				}
			}
			break;

		case WM_NOTIFY:
		{
			NMHDR *hdr = (NMHDR*)lParam;

			if (wParam == IDC_RICHCERTLIST)
			{
				if (hdr->code == LVN_ITEMCHANGED)
				{
					return params->OnChangeRichEdit();
				}
				if (hdr->code == (UINT)NM_DBLCLK)
				{
					return params->OnDblclkCertList();
				}
			}
			else if (wParam == IDC_GROUPLIST)
			{
				if (hdr->code == LVN_ITEMCHANGED)
				{
					return params->OnChangeGroupList();
				}
				if (hdr->code == (UINT)NM_DBLCLK)
				{
					return params->OnDblclkGrouplist();
				}
			}
		}
		break;

		case WM_POSTINIT:
			return params->InitSettings();

			//case WM_CRYPTOGROUPLOGIN:
			//	return params->CryptoGroupPressLogin();
		case WM_TOKENCHANGE_ADD:
			// TODO:  Implement me when we have token change detection
			//params->OnTokenAdd(wParam, lParam);
			return TRUE;
		case WM_TOKENCHANGE_REMOVE:
			// TODO:  Implement me when we have token change detection
			//params->OnTokenRemove(wParam, lParam);
			return TRUE;
		case WM_TOKENCHANGE_CHANGE:
			// TODO:  Implement me     params->OnTokenDataChange(wParam, lParam);
			return TRUE;
		case WM_TIMER:
			params->OnTimer();
			return TRUE;
		}
		return FALSE;
	}
    intptr_t OnInitDialog()
	{
		_GroupCtrl = GetDlgItem(_hDlg, IDC_GROUPLIST);
		_RichCertList = GetDlgItem(_hDlg, IDC_RICHCERTLIST);
		_FavoriteCombo = GetDlgItem(_hDlg, IDC_FAVORITECOMBO);
		//		_CryptoGroupCombo = GetDlgItem(_hDlg, IDC_CRYPTOGROUPCOMBO);
		_TokenCombo = GetDlgItem(_hDlg, IDC_TOKENCOMBO);
		_PKIHidden = false;

		/* Activate the favorite combo at first.  Will be disabled later if necessary. */
		EnableWindow(_FavoriteCombo, TRUE);

		// create a single column in the group List Control
		RECT rect;
		LVCOLUMNA column;
		GetClientRect(_GroupCtrl, &rect);
		memset(&column, 0, sizeof(column));
		column.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT;
		column.fmt = LVCFMT_LEFT;
		column.cx = rect.right - rect.left;
		column.pszText = ("");
		ListView_InsertColumn(_GroupCtrl, 0, &column);

		// turn on full row selection
		DWORD style = GetWindowLong(_GroupCtrl, GWL_EXSTYLE);
		SetWindowLong(_GroupCtrl, GWL_EXSTYLE, style | LVS_EX_FULLROWSELECT | LVS_EX_LABELTIP);

		// turn on word wrap in the Rich Edit control
		//SendMessage(_RichCertList, EM_SETTARGETDEVICE, 0, 0);
		//DWORD mask = (DWORD)SendMessage(_RichCertList, EM_GETEVENTMASK, 0, 0);
		//mask |= ENM_SELCHANGE;
		//SendMessage(_RichCertList, EM_SETEVENTMASK, 0, mask);

		GetClientRect(_RichCertList, &rect);
		memset(&column, 0, sizeof(column));
		column.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT;
		column.fmt = LVCFMT_LEFT;
		column.cx = rect.right - rect.left;
		column.pszText = ("");
		ListView_InsertColumn(_RichCertList, 0, &column);

		style = GetWindowLong(_RichCertList, GWL_EXSTYLE);
		SetWindowLong(_RichCertList, GWL_EXSTYLE, style | LVS_EX_FULLROWSELECT | LVS_EX_LABELTIP);

		// TODO:  Enable PKI support here
		BOOL bHasEncryptionCert = FALSE;

		// Hide the PKI controls unless we have a cert or AlwaysShowPKI is TRUE
		if ((_NeverShowPKI) ||
			((!_AlwaysShowPKI) && (!bHasEncryptionCert)))
			HidePKIControls();

		// If we have a cert, initialize  "Use My Encryption Cert" to TRUE
		if (bHasEncryptionCert)
		{
			SendDlgItemMessage(_hDlg, IDC_USE_MY_CERT, BM_SETCHECK, BST_CHECKED, 0);
		}

		// if we don't have a cert or require the user to encrypt with their
		// personal cert, disable the checkbox so it can't be changed.
		if (!bHasEncryptionCert || _RequireEncCert)
		{
			EnableWindow(GetDlgItem(_hDlg, IDC_USE_MY_CERT), FALSE);
		}

		// change controls based on settings of _CreateFavorites
		if (_CreateFavorites) {
			RECT rectOk, rectCreate;

			SetWindowTextA(_hDlg, "Manage Favorites");
			SetWindowTextA(GetDlgItem(_hDlg, IDCANCEL), "&Close");
			SetWindowTextA(GetDlgItem(_hDlg, IDC_CREATE_FAVORITE), "Create &Favorite");
			ShowWindow(GetDlgItem(_hDlg, IDOK), SW_HIDE);

			// rename and resize the "Create Favorite" button
			GetWindowRect(GetDlgItem(_hDlg, IDC_CREATE_FAVORITE), &rectCreate);
			ScreenToClient(_hDlg, ((POINT*)&rectCreate) + 0);
			ScreenToClient(_hDlg, ((POINT*)&rectCreate) + 1);
			rectCreate.right += 10;
			MoveWindow(GetDlgItem(_hDlg, IDC_CREATE_FAVORITE), rectCreate.left, rectCreate.top, rectCreate.right - rectCreate.left, rectCreate.bottom - rectCreate.top, TRUE);
			MoveWindow(GetDlgItem(_hDlg, IDC_DELETE_FAVORITE), rectCreate.right + 10, rectCreate.top, rectCreate.right - rectCreate.left, rectCreate.bottom - rectCreate.top, TRUE);

			GetWindowRect(GetDlgItem(_hDlg, IDOK), &rectOk);
			ScreenToClient(_hDlg, ((POINT*)&rectOk) + 0);
			ScreenToClient(_hDlg, ((POINT*)&rectOk) + 1);
			MoveWindow(GetDlgItem(_hDlg, IDHELP), rectOk.left, rectOk.top, rectOk.right - rectOk.left, rectOk.bottom - rectOk.top, TRUE);
		}
		else
		{
			ShowWindow(GetDlgItem(_hDlg, IDC_DELETE_FAVORITE), SW_HIDE);
		}

		EnableDisableOK();

		// now, select a token and login to it (after the dialog comes up)
		PostMessage(_hDlg, WM_POSTINIT, 0, 0);

		return TRUE;
	}
	void OnWmDestroy()
	{
		// TODO:  Change detection needed here
		//if (m_tokenChangeCookie != 0)
		//{
		//	gMonitor->UnregisterChangeConsumer(m_tokenChangeCookie);
		//	for (int i = 0; i < (int)gConsumerCookieList.count(); i++)
		//	{
		//		if (gConsumerCookieList[i] == m_tokenChangeCookie)
		//		{
		//			gConsumerCookieList.removeAtIndex(i);
		//			break;
		//		}
		//	}
		//	m_tokenChangeCookie = 0;
		//}
		//m_tokenChange.reset();
	}
    intptr_t OnOK()
	{
		//int index;
		int count;

		// TODO:  Implement me when we support PKI
		//
		//    /* If we have certs selected but the PKI window is hidden, we should prompt the user to
		//       indicate whether they want selection to continue.  This should only occur if a favorite
		//       with a cert has been selected. */
		//    if (myPKIHidden && (mySelectedCertVector.size() > 0))
		//    {
		//       if ( IDCANCEL == MessageBox("The favorite selected contains at least one certificate.  Continue with selection?",
		//                                  "CKM Audience Selector Dialog",
		//                                  MB_OKCANCEL) )
		//       {
		//           /* Just return if they didn't want to continue. */
		//           return TRUE;
		//       }
		//    }

		// TODO:  Implement second term when we support PKI
		// get the number of access groups in the list
		if (0 == (count = (int)SendMessage(_GroupCtrl, LVM_GETITEMCOUNT, 0, 0)) /*&&
																				 (0 == mySelectedCertVector.size())*/) {
			MessageBoxA(_hDlg, "You haven't selected any Groups or People.", "Error", MB_ICONHAND | MB_OK);
			return TRUE;
		}

		// TODO:  Implement me when we support PKI
		//    CKMSystemPrefs sysPrefs;
		//    CKMBOOL bHasEncryptionCert = sysPrefs.hasEncryptionCert();
		//
		//    if (mySelectedCertVector.size() > 0) {
		//        int result;
		//        CKMUINT4 userCertStatus;
		//        CKMCertificate userCert;
		//        CKMAccessGroup userCertAg;
		//
		//        CKMVerifyPrefs verifyPrefs;
		//        verifyPrefs = sysPrefs.getVerifyPrefs();
		//
		//        // if there are certs present, add our personal cert to the cert list
		//        // another option would be to do this ONLY if no CKM groups are present
		//        if (bHasEncryptionCert && ((CButton *)GetDlgItem(IDC_USE_MY_CERT))->GetCheck()) {
		//            // must validate personal cert first
		//            CWaitCursor wc;
		//            userCert = sysPrefs.getEncryptionCert();
		//            userCertStatus = userCert.verify(verifyPrefs);
		//            if (CKMCertIsUnusable(userCertStatus)) {
		//                CString str;
		//                if (userCertStatus & CKMF_CERT_REVOKED) {
		//                    str.Format("Your personal Encryption Certificate has been revoked and\n"
		//                        "it cannot be used to encrypt this data. As a result, you may not\n"
		//                        "be able to decrypt the resulting output. Do you wish to continue?");
		//                } else {
		//                    str.Format("There is a problem with your personal Encryption Certificate\n"
		//                        "and it cannot be used to encrypt this data. As a result, you may not\n"
		//                        "be able to decrypt the resulting output. Do you wish to continue?");
		//                }
		//
		//                result = ::MessageBox(CKMUI_Env::GetRootWindow(), str, myAppTitle, MB_YESNO | MB_ICONWARNING);
		//                if (result == IDNO)
		//                    return;
		//            }
		//        }
		//
		//        // run the cert status resolver to make sure the selections are OK
		//        CertStatusResolver csr(&mySelectedCertVector, &verifyPrefs);
		//        result = csr.DoModal();
		//
		//        UpdateCertDisplay();
		//
		//        if (result == IDCANCEL)
		//            return;
		//
		//        if (! mySelectedGroupVector.size() && ! mySelectedCertVector.size()) {
		//                //AfxError("You haven't selected any Groups or People.");
		//                return;
		//            }
		//
		//        // finally, add the user's cert to the list of certs
		//        if (bHasEncryptionCert && ((CButton *)GetDlgItem(IDC_USE_MY_CERT))->GetCheck()) {
		//            if (! CKMCertIsUnusable(userCertStatus)) {
		//                userCertAg.setCert(userCert);
		//                mySelectedCertVector.push_back(userCertAg);
		//            }
		//        }
		//    }

		EndDialog(_hDlg, IDOK);
		resetConsumer();
		return TRUE;
	}
	void resetConsumer()
	{
		// TODO:  Change detection needed here
		//std::shared_ptr<AS_ChangeConsumer> con = changeConsumer;

		//changeConsumer.reset();
		//if (!!con)
		//	con->Disconnect();
	}
    intptr_t OnHelp()
	{
		std::shared_ptr<IVEILHelpRegistry> help = ::TopServiceLocator()->get_instance<IVEILHelpRegistry>("/WinAPI/HelpRegistry");

		if (!help)
		{
			MessageBoxA(_hDlg, ("Help is not available at this time."), ("Status"), MB_OK);
		}
		else
		{
			help->DisplayHelpForWindowId(winid_AudienceSelector, (XP_WINDOW)_hDlg);
		}
		return FALSE;
	}
    intptr_t OnUseMyCert()
	{
		// TODO:  Implement me
		return FALSE;
	}
    intptr_t OnGroupAdd()
	{
		// if nothing is selected, display an error
		if (-1 == SendMessage(_TokenCombo, CB_GETCURSEL, 0, 0)) {
			return FALSE;
		}

		// make sure we are logged in to the selected token
		if (FALSE == CheckLogin())
		{
			//myActiveToken = NULL;
			return FALSE;
		}

		// make sure we have the CryptoGroup object
		if (!_ActiveCryptoGroup)
		{
			MessageBoxA(_hDlg, "OnGroupAdd: No Crypto Group selected, or selected Crypto Group is invalid.", "Error", MB_ICONHAND | MB_OK);
			return FALSE;
		}

		if (!_header)
		{
			//ConstructHeader();
			//if (!_header)
			return FALSE;
		}

		std::shared_ptr<ICmsHeaderAccessGroup> andGroup;
		std::shared_ptr<ICmsHeaderAttributeGroup> attrGroup;
		std::shared_ptr<ICmsHeaderExtension> ext;
		std::shared_ptr<ICmsHeaderAccessGroupExtension> groupList;

		if (!_header->GetProtectedExtensionByOID(tscrypto::tsCryptoData(id_TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), ext))
		{
			if (!_header->AddProtectedExtension(tscrypto::tsCryptoData(id_TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), true, ext))
			{
				MessageBoxA(_hDlg, "OnGroupAdd: Unable to add a new access group list to the CKM Header.", "Error", MB_ICONHAND | MB_OK);
				return FALSE;
			}
		}
		if (!(groupList = std::dynamic_pointer_cast<ICmsHeaderAccessGroupExtension>(ext)))
		{
			return FALSE;
		}
		ext.reset();

		if (!(groupList->AddAccessGroup(ag_Attrs, andGroup)) || !(attrGroup = std::dynamic_pointer_cast<ICmsHeaderAttributeGroup>(andGroup)))
		{
			MessageBoxA(_hDlg, "OnGroupAdd: Unable to add a new attribute list to the CKM Header.", "Error", MB_ICONHAND | MB_OK);
			if (!!andGroup)
			{
				groupList->RemoveAccessGroup(groupList->GetAccessGroupCount() - 1);
				andGroup.reset();
			}
			return FALSE;
		}

		std::shared_ptr<ICmsHeaderAttributeListExtension> attrList;

		if (!_header->GetProtectedExtensionByOID(tscrypto::tsCryptoData(id_TECSEC_CKMHEADER_V7_ATTRIBUTELIST_EXT_OID, tscrypto::tsCryptoData::OID), ext))
		{
			if (!_header->AddProtectedExtension(tscrypto::tsCryptoData(id_TECSEC_CKMHEADER_V7_ATTRIBUTELIST_EXT_OID, tscrypto::tsCryptoData::OID), true, ext))
			{
				MessageBoxA(_hDlg, "OnGroupAdd: Unable to add a new attribute list to the CKM Header.", "Error", MB_ICONHAND | MB_OK);
				return FALSE;
			}
		}

		if (!(attrList = std::dynamic_pointer_cast<ICmsHeaderAttributeListExtension>(ext)))
		{
			MessageBoxA(_hDlg, "OnGroupAdd: Unable to add a new attribute list to the CKM Header.", "Error", MB_ICONHAND | MB_OK);
			return FALSE;
		}
		ext.reset();

		std::shared_ptr<IAttributeSelector> attrSel;

		if (!(attrSel = ::TopServiceLocator()->get_instance<IAttributeSelector>("/WinAPI/AttributeSelectorGrid")))
		{
			attrGroup.reset();
			groupList->RemoveAccessGroup(groupList->GetAccessGroupCount() - 1);
			andGroup.reset();
		}
		else
		{
			if (!attrSel->Start(Session(), (XP_WINDOW)_hDlg, _ActiveCryptoGroup->get_Id(), attrGroup, attrList) || attrSel->DisplayModal() != IDOK)
			{
				attrGroup.reset();
				groupList->RemoveAccessGroup(groupList->GetAccessGroupCount() - 1);
				andGroup.reset();
			}
		}
		if (!!attrGroup)
		{
			// make sure we don't already have an identical access group
			if (!CheckAccessGroup(attrGroup)) {
				attrGroup.reset();
				groupList->RemoveAccessGroup(groupList->GetAccessGroupCount() - 1);
				andGroup.reset();
				MessageBoxA(_hDlg, "You already have an access group with the same Attributes.", "Error", MB_ICONHAND | MB_OK);
				return FALSE;
			}
		}
		RebuildAccessGroupList();

		EnableDisableOK();
		return FALSE;
	}
    intptr_t OnGroupDelete()
	{
		int index;

		index = (int)SendMessage(_GroupCtrl, LVM_GETNEXTITEM, (WPARAM)-1, MAKELPARAM(LVNI_SELECTED, 0));
		if (-1 == index) {
			MessageBoxA(_hDlg, "Unable to delete... No access group is selected.", "Error", MB_ICONHAND | MB_OK);
			return TRUE;
		}

		std::shared_ptr<ICmsHeaderExtension> ext;
		std::shared_ptr<ICmsHeaderAccessGroupExtension> extGroup;
		std::shared_ptr<ICmsHeaderAccessGroup> andGroup;

		if (!_header || !_header->GetProtectedExtensionByOID(tscrypto::tsCryptoData(id_TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), ext) ||
			!(extGroup = std::dynamic_pointer_cast<ICmsHeaderAccessGroupExtension>(ext)))
		{
			MessageBoxA(_hDlg, "Unable to delete... The access group list is not available.", "Error", MB_ICONHAND | MB_OK);
			return TRUE;
		}
		ext.reset();

		uint32_t count = (uint32_t)extGroup->GetAccessGroupCount();
		for (uint32_t i = 0; i < count && index >= 0; i++)
		{
			andGroup.reset();
			if ((extGroup->GetAccessGroup(i, andGroup)) && (andGroup->GetAndGroupType() == ag_Attrs))
			{
				if (index == 0)
				{
					if (!(extGroup->RemoveAccessGroup(i)))
					{
						MessageBoxA(_hDlg, "Unable to delete... The selected access group was not located.", "Error", MB_ICONHAND | MB_OK);
						return TRUE;
					}
					SendMessage(_GroupCtrl, LVM_DELETEITEM, (WPARAM)index, 0);
				}
				index--;
			}
		}

		RebuildAccessGroupList();

		// remove the access group from the display list,
		SetItemSelected(index);
		UpdateDialogControls();
		EnableDisableOK();

		return FALSE;
	}

    intptr_t OnCertDelete()
	{
		int index;

		index = (int)SendMessage(_RichCertList, LVM_GETNEXTITEM, (WPARAM)-1, MAKELPARAM(LVNI_SELECTED, 0));
		if (-1 == index) {
			MessageBoxA(_hDlg, "Unable to delete... No certificate/password group is selected.", "Error", MB_ICONHAND | MB_OK);
			return TRUE;
		}

		std::shared_ptr<ICmsHeaderExtension> ext;
		std::shared_ptr<ICmsHeaderAccessGroupExtension> extGroup;
		std::shared_ptr<ICmsHeaderAccessGroup> andGroup;

		if (!_header || !_header->GetProtectedExtensionByOID(tscrypto::tsCryptoData(id_TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), ext) ||
			!(extGroup = std::dynamic_pointer_cast<ICmsHeaderAccessGroupExtension>(ext)))
		{
			MessageBoxA(_hDlg, "Unable to delete... The access group list is not available.", "Error", MB_ICONHAND | MB_OK);
			return TRUE;
		}
		ext.reset();

		uint32_t count = (uint32_t)extGroup->GetAccessGroupCount();
		for (uint32_t i = 0; i < count && index >= 0; i++)
		{
			andGroup.reset();
			if ((extGroup->GetAccessGroup(i, andGroup)) && (andGroup->GetAndGroupType() == ag_FullCert ||
				andGroup->GetAndGroupType() == ag_PartialCert || andGroup->GetAndGroupType() == ag_Pin))
			{
				if (index == 0)
				{
					if (!(extGroup->RemoveAccessGroup(i)))
					{
						MessageBoxA(_hDlg, "Unable to delete... The selected access group was not located.", "Error", MB_ICONHAND | MB_OK);
						return TRUE;
					}
					SendMessage(_RichCertList, LVM_DELETEITEM, (WPARAM)index, 0);
				}
				index--;
			}
		}
		//RebuildAccessGroupList();

		// remove the access group from the display list,
		SetItemSelected(index);
		UpdateDialogControls();
		EnableDisableOK();

		return FALSE;
	}

    intptr_t OnGroupEdit()
	{
		int index;

		std::shared_ptr<ICmsHeaderAttributeGroup> attrs;
		std::shared_ptr<ICmsHeaderAccessGroup> accessGroup;

		index = (int)SendMessage(_GroupCtrl, LVM_GETNEXTITEM, (WPARAM)-1, MAKELPARAM(LVNI_SELECTED, 0));
		if (-1 == index) {
			MessageBoxA(_hDlg, "Unable to edit... No access group is selected.", "Error", MB_ICONHAND | MB_OK);
			return TRUE;
		}

		if (!FindSelectedAccessGroup(accessGroup, attrs))
		{
			MessageBoxA(_hDlg, "Unable to edit... The selected access group was not located.", "Error", MB_ICONHAND | MB_OK);
			return TRUE;
		}

		std::shared_ptr<ICmsHeader> newHeader;

		if (!(newHeader = ::TopServiceLocator()->get_instance<ICmsHeader>("/CmsHeader")))
		{
			MessageBoxA(_hDlg, "Unable to edit... Unable to create a CKM Header.", "Error", MB_ICONHAND | MB_OK);
			return FALSE;
		}

		std::shared_ptr<ICmsHeaderAccessGroup> andGroup;
		std::shared_ptr<ICmsHeaderAttributeGroup> attrGroup;
		std::shared_ptr<ICmsHeaderExtension> ext;
		std::shared_ptr<ICmsHeaderAccessGroupExtension> extGroup;

		if (!newHeader->GetProtectedExtensionByOID(tscrypto::tsCryptoData(id_TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), ext))
		{
			newHeader->AddProtectedExtension(tscrypto::tsCryptoData(id_TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), true, ext);
		}

		if (!ext || !(extGroup = std::dynamic_pointer_cast<ICmsHeaderAccessGroupExtension>(ext)))
		{
			MessageBoxA(_hDlg, "Unable to delete... The access group list is not available.", "Error", MB_ICONHAND | MB_OK);
			return TRUE;
		}
		ext.reset();

		if (!(extGroup->AddAccessGroup(ag_Attrs, andGroup)) || !(attrGroup = std::dynamic_pointer_cast<ICmsHeaderAttributeGroup>(andGroup)))
		{
			MessageBoxA(_hDlg, "Unable to edit... Unable to add a new attribute list to the CKM Header.", "Error", MB_ICONHAND | MB_OK);
			return FALSE;
		}
		int count = (int)attrs->GetAttributeCount();
		for (int i = 0; i < count; i++)
		{
			attrGroup->AddAttributeIndex(attrs->GetAttributeIndex(i));
		}

		std::shared_ptr<ICmsHeaderAttributeListExtension> attrsList;

		if (!_header || !_header->GetProtectedExtensionByOID(tscrypto::tsCryptoData(id_TECSEC_CKMHEADER_V7_ATTRIBUTELIST_EXT_OID, tscrypto::tsCryptoData::OID), ext))
		{
			if (!_header || !_header->AddProtectedExtension(tscrypto::tsCryptoData(id_TECSEC_CKMHEADER_V7_ATTRIBUTELIST_EXT_OID, tscrypto::tsCryptoData::OID), true, ext))
			{
				MessageBoxA(_hDlg, "Unable to edit... Unable to retrieve the attribute list.", "Error", MB_ICONHAND | MB_OK);
				return FALSE;
			}
		}

		if (!(attrsList = std::dynamic_pointer_cast<ICmsHeaderAttributeListExtension>(ext)))
		{
			MessageBoxA(_hDlg, "Unable to edit... Unable to retrieve the attribute list.", "Error", MB_ICONHAND | MB_OK);
			return FALSE;
		}
		ext.reset();

		std::shared_ptr<IAttributeSelector> attrSel;

		if (!(attrSel = ::TopServiceLocator()->get_instance<IAttributeSelector>("/WinAPI/AttributeSelectorGrid")))
		{
			return TRUE;
		}
		if (!attrSel->Start(Session(), (XP_WINDOW)_hDlg, _ActiveCryptoGroup->get_Id(), attrGroup, attrsList) || attrSel->DisplayModal() != IDOK)
		{
			return TRUE;
		}

		count = (int)attrGroup->GetAttributeCount();

		while (attrs->GetAttributeCount() > 0)
			attrs->RemoveAttributeIndex(0);
		for (int i = 0; i < count; i++)
		{
			attrs->AddAttributeIndex(attrGroup->GetAttributeIndex(i));
		}

		RebuildAccessGroupList();

		// remove the access group from the display list,
		SetItemSelected(index);
		UpdateDialogControls();
		EnableDisableOK();

		return FALSE;
	}

    intptr_t OnCreateFavorite()
	{
		std::shared_ptr<ICmsHeaderExtension> ext;
		std::shared_ptr<ICmsHeaderAccessGroupExtension> groupList;

		if (!_header || !_header->GetProtectedExtensionByOID(tscrypto::tsCryptoData(id_TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), ext) ||
			!(groupList = std::dynamic_pointer_cast<ICmsHeaderAccessGroupExtension>(ext)) || groupList->GetAccessGroupCount() == 0)
		{
			MessageBoxA(_hDlg, "No access groups have been created.", "Error", MB_ICONHAND | MB_OK);
			return FALSE;
		}

		GUID id = GUID_NULL;

		if (_CurFavIndex == 0)
		{
			tscrypto::tsCryptoString favName;
			std::shared_ptr<IFavoriteName> dlg = ::TopServiceLocator()->get_instance<IFavoriteName>("/WinAPI/FavoriteName");

			if (!HasSession() || !Session()->IsValid() || !_connector || !dlg || !dlg->Start((XP_WINDOW)_hDlg) || dlg->DisplayModal() != IDOK)
				return FALSE;

			favName = dlg->Name();
			if (GetProfile()->exists_SerialNumber())
				id = _connector->CreateFavorite(*GetProfile()->get_SerialNumber(), _header->ToBytes(), favName);
			if (id == GUID_NULL)
			{
				MessageBoxA(_hDlg, "An error occurred while attempting to create the new favorite.", "Error", MB_ICONHAND | MB_OK);
				return FALSE;
			}
			if (SendMessage(_FavoriteCombo, CB_FINDSTRING, 0, (LPARAM)favName.c_str()) == -1)
			{
				int index = (int)SendMessage(_FavoriteCombo, CB_ADDSTRING, 0, (LPARAM)favName.c_str());
				SendMessage(_FavoriteCombo, CB_SETITEMDATA, index, findGuidIndex(id, true));
			}
			return FALSE;
		}
		else
		{
			LRESULT idx = SendMessage(_FavoriteCombo, CB_GETITEMDATA, _CurFavIndex, 0);

			if (idx >= 0 && idx < (LRESULT)_guidMap.size())
			{
				id = _guidMap[idx];
			}
		}

		if (id != GUID_NULL || !_connector)
		{
			if (!_connector->UpdateFavorite(id, _header->ToBytes()))
			{
				MessageBoxA(_hDlg, "An error has occurred while updating the favorite.", "Error", MB_ICONHAND | MB_OK);
				return FALSE;
			}
			if (_CurFavIndex > 0)
			{
				MessageBox(_hDlg, "The favorite has been updated.", "Updated", MB_OK);
			}
		}
		else
		{
			MessageBoxA(_hDlg, "The selected favorite could not be found.", "Error", MB_ICONHAND | MB_OK);
			return FALSE;
		}

		return FALSE;
	}

    intptr_t OnDeleteFavorite()
	{
		if (_CurFavIndex == 0)
		{
			return FALSE;
		}

		GUID id = GUID_NULL;
		LRESULT idx = SendMessage(_FavoriteCombo, CB_GETITEMDATA, _CurFavIndex, 0);

		if (idx >= 0 && idx < (LRESULT)_guidMap.size())
		{
			id = _guidMap[idx];
		}

		if (id == GUID_NULL || !_connector)
		{
			MessageBoxA(_hDlg, "An error occurred while attempting to retrieve the favorite.", "Error", MB_ICONHAND | MB_OK);
			return FALSE;
		}
		if (!_connector->DeleteFavorite(id))
		{
			MessageBoxA(_hDlg, "An error occurred while attempting to delete the favorite.", "Error", MB_ICONHAND | MB_OK);
			return FALSE;
		}
		_CurFavIndex = 0;
		InitFavorites();
		if (!!_header)
			_header->Clear();

		UpdateDialogControls();
		EnableDisableOK();
		return FALSE;
	}
    intptr_t OnPeople()
	{
		MessageBox(NULL, "People selected", "INFO", MB_OK);
		// TODO:  Implement me
		return FALSE;
	}

    intptr_t OnPassword()
	{
		//tscrypto::tsCryptoString description;

		//if (!!_header)
		//{
		//	if (CreatePasswordEntryDlg(description, _hDlg))
		//	{
		//		std::shared_ptr<ICmsHeaderExtension> ext;
		//		std::shared_ptr<ICmsHeaderAccessGroupExtension> extGroup;
		//		std::shared_ptr<ICmsHeaderAccessGroup> andGroup;
		//		std::shared_ptr<ICmsHeaderPinGroup> pinGroup;

		//		if (!_header->GetProtectedExtensionByOID(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), ext))
		//		{
		//			if (!_header->AddProtectedExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), true, ext))
		//			{
		//				MessageBoxA(_hDlg, "OnGroupAdd: Unable to add a new access group list to the CKM Header.", "Error", MB_ICONHAND | MB_OK);
		//				return FALSE;
		//			}
		//		}
		//		if (!(extGroup = std::dynamic_pointer_cast<ICmsHeaderAccessGroupExtension>(ext)))
		//		{
		//			return FALSE;
		//		}
		//		ext.reset();

		//		if (!(extGroup->AddAccessGroup(ag_Pin, &andGroup)) || FAILED(andGroup->QueryInterface(&pinGroup)))
		//		{
		//			MessageBoxA(_hDlg, "OnGroupAdd: Unable to add a new access group list to the CKM Header.", "Error", MB_ICONHAND | MB_OK);
		//			return FALSE;
		//		}
		//		pinGroup->SetDescription(description);
		//		this->AddCertText(this->BuildPinLine(pinGroup).c_str());
		//		EnableDisableOK();
		//	}
		//}
		return FALSE;
	}

	//intptr_t OnCryptoGroupBoxPress()
	//{
	//	PostMessage(_hDlg, WM_CRYPTOGROUPLOGIN, 0, 0);
	//	return FALSE;
	//}

	//intptr_t CryptoGroupKeyPressLogin()
	//{
	//	return populateCryptoGroupList();
	//}

	Asn1::CTS::_POD_CryptoGroup* GetCGbyGuid(const tscrypto::tsCryptoData& id)
	{
		if (!HasSession() || !Session()->IsValid() || !HasProfile())
			return nullptr;

		if (GetProfile()->exists_cryptoGroupList())
		{
			for (uint32_t i = 0; i < GetProfile()->get_cryptoGroupList()->size(); i++)
			{
				if (GetProfile()->get_cryptoGroupList()->get_at(i).get_Id() == id)
				{
					return &GetProfile()->get_cryptoGroupList()->get_at(i);
				}
			}
		}
		return nullptr;
	}

	int findCgByGuid(const tscrypto::tsCryptoData& id)
	{
		if (!HasSession() || !Session()->IsValid() || !HasProfile() || !GetProfile()->exists_cryptoGroupList() || GetProfile()->get_cryptoGroupList()->size() == 0)
			return -1;

		for (uint32_t i = 0; i < GetProfile()->get_cryptoGroupList()->size(); i++)
		{
			if (GetProfile()->get_cryptoGroupList()->get_at(i).get_Id() == id)
				return (int)i;
		}
		return -1;
	}

	BOOL LoadFavoriteForToken(std::shared_ptr<IFavorite> fav, std::shared_ptr<ICmsHeader> favHeader)
	{
		//    int index;
		//    int count;

		// get rid of the old CryptoGroup and token
		_ActiveCryptoGroup = nullptr;

		// empty out the old attribute and cert lists
		// Must loop through and delete all access groups in the grouplist control that we have stored
		// previously. 
		SendMessage(_GroupCtrl, LVM_DELETEALLITEMS, 0, 0);
		AddGroupText(AS_SEL_DOM_STR);
		EnableWindow(_GroupCtrl, FALSE);

		if (!HasSession())
		{
			return false;
		}

		if (!Session()->IsValid() || !Session()->IsLoggedIn())
		{
			std::shared_ptr<ITokenLogin> login = ::TopServiceLocator()->try_get_instance<ITokenLogin>("/WinAPI/TokenLogIn");;

			if (!!login)
			{
				if (!login->Start(Session(), (XP_WINDOW)_hDlg) || login->DisplayModal() != IDOK)
					return false;
			}
			else
				return false;
		}
		if (!HasSession() || !Session()->IsValid() || !HasProfile() || fav->enterpriseId() != GetProfile()->get_EnterpriseId())
		{
			return false;
		}

		std::shared_ptr<ICkmOperations> ops = std::dynamic_pointer_cast<ICkmOperations>(favHeader);

		if (!!ops)
		{
			if (!ops->CanGenerateWorkingKey(Session()))
			{
				return false;
			}
		}


		// TODO:  Implement when PKI supported
		//    mySelectedCertVector.clear();
		//SendMessage(_CryptoGroupCombo, CB_RESETCONTENT, 0, 0);
		//SendMessage(_CryptoGroupCombo, CB_SETCURSEL, (WPARAM)(-1), 0);

		UpdateDialogControls();
		EnableDisableOK();

		//PR 3115 Favorite not tied to a particular Token

		// If there is a token in this favorite, login.  Otherwise, don't login.  
		//if (fav->tokenSerialNumber().size() != '\0')
		{
			Asn1::CTS::_POD_CryptoGroup* tempCG = nullptr;
			std::shared_ptr<ICmsHeaderCryptoGroup> hCG;
			std::shared_ptr<ICmsHeader> fav_header;
            tscrypto::tsCryptoData cgGuid;

			// set the token selection and re-read the fiefdom list
			////_TokenCombo.SetCurSel(index); // RDBJ use the currently selected token

			LoginTokenPressed();

			if (!(fav_header = ::TopServiceLocator()->try_get_instance<ICmsHeader>("/CmsHeader")))
			{
				//fav->Delete();
				SendMessage(_FavoriteCombo, CB_SETCURSEL, (WPARAM)(0), 0);
				return FALSE;
			}
			fav_header->FromBytes(fav->headerData());

			if (fav_header->GetCryptoGroupCount() > 0 && (!(fav_header->GetCryptoGroup(0, hCG))))
			{
				//fav->Delete();
				SendMessage(_FavoriteCombo, CB_SETCURSEL, (WPARAM)(0), 0);
				return FALSE;
			}
			if (!!hCG && HasSession())
			{
				cgGuid = hCG->GetCryptoGroupId();
				// now we have to find the proper fiefdom
				//if (!!(tempCG = GetCGbyGuid(cgGuid)))
				//{
					//int index = findCgByGuid(cgGuid);
					//int cgIndex;
					//int cgCount;
					//
					//cgCount = (int)SendMessage(_CryptoGroupCombo, CB_GETCOUNT, 0, 0);
					//for (cgIndex = 0; cgIndex < cgCount; cgIndex++)
					//{
					//	if (index == SendMessage(_CryptoGroupCombo, CB_GETITEMDATA, cgIndex, 0))
					//	{
					//		SendMessage(_CryptoGroupCombo, CB_SETCURSEL, cgIndex, 0);
					//		break;
					//	}
					//}
					//if (cgIndex >= cgCount)
					//{
					//	SendMessage(_CryptoGroupCombo, CB_SETCURSEL, (WPARAM)-1, 0);
					//}
				//}

				//OnChangeCryptoGroup();

				// Verify we are logged in or log in to the currently selected token.
				if (!CheckLogin())
				{
					return FALSE;
				}
			}
			else
			{
				//SendMessage(_CryptoGroupCombo, CB_SETCURSEL, (WPARAM)-1, 0);
				//OnChangeCryptoGroup();
			}
			_header.reset();
			_header = fav_header;
		}

		// now populate the access group control with the Favorites attributes if all match on the Token
		RebuildAccessGroupList();

		// TODO: Implement me when PKI is supported
		//    CKMAccessGroup * newAg;
		//    CKMVector<CKMAccessGroup>::iterator agIter;
		//    CKMBOOL bCertMissing = CKMFALSE;
		//    for (agIter = fav->agVec.begin(); agIter != fav->agVec.end(); agIter++)
		//    {
		//        if (agIter->getType() == CKM_AGTYPE_FULL_CERT)
		//        {
		//            CKMAccessGroup certAg = *agIter;
		//            if (FALSE == (certSel.LookupCert(certAg)))
		//            {
		//                // Missing at least one cert so prepare to notify user of fact
		//                bCertMissing = CKMTRUE;
		//                continue;
		//            }
		//            mySelectedCertVector.push_back(certAg);
		//        } else if (agIter->getType() == CKM_AGTYPE_ATTRS)
		//        {
		//            newAg = new CKMAccessGroup;
		//            if (FALSE == LookupAttributes(&*agIter, newAg))
		//            {
		//                delete newAg;
		//                return FALSE;
		//            }
		//
		//            /* WARNING WARNING....Although generally undocumented, AddAccessGroup() takes the
		//            pointer passed in and saves it in the _GroupCtrl list as a data pointer.  These
		//            pointers must be cleaned up when the DeleteAllItems() method is called on
		//            _GroupCtrl. */
		//            if (FALSE == AddAccessGroup(newAg))
		//            {
		//                /* Make sure we clean up all previously added ags. */
		//                for (int i = 0; i < _GroupCtrl.GetItemCount(); i++)
		//                {
		//                    pDeleteMeAG = (CKMAccessGroup *)_GroupCtrl.GetItemData(i);
		//                    delete pDeleteMeAG;
		//                }
		//                _GroupCtrl.DeleteAllItems();
		//                _GroupCtrl.InsertItem(0,AS_SEL_DOM_STR);
		//                _GroupCtrl.EnableWindow(FALSE);
		//                delete newAg;
		//                return FALSE;
		//            }
		//            /* Cannot delete newAg here because it is saved in AddAccessGroup above.  Ya gotta luv it! */
		//            //delete newAg;
		//        }
		//    }
		//
		//    if (bCertMissing)
		//    {
		//        MessageBox("At least one certificate could not be found in your certificate store.",
		//                "CKM Audience Selector Dialog");
		//    }
		//    // update the certificate display
		//    UpdateCertDisplay();
		return TRUE;
	}

	void LoginTokenPressed()
	{
		if (!HasSession())
		{
			MessageBoxA(_hDlg, "Please select a token before pressing the log in button.", "Warning", MB_ICONHAND | MB_OK);
			return;
		}

		//if (!_session->isValid())
		//{
		//	MessageBoxA(_hDlg, "The selected token is not available for use at this time.  Please select a different token.", "Warning", MB_ICONHAND | MB_OK);
		//	return FALSE;
		//}

		if (!Session()->IsValid() || !Session()->IsLoggedIn())
			CheckLogin();
		EnableWindow(GetDlgItem(_hDlg, IDC_TOKEN_LOGIN), HasSession() && !Session()->IsLoggedIn());

		if (Session()->IsLoggedIn())
		{
			SendMessage(_GroupCtrl, LVM_DELETEALLITEMS, 0, 0);
			EnableWindow(_GroupCtrl, TRUE);
			UpdateDialogControls();
		}
	}
    intptr_t OnChangeFavorite()
	{
		int favIndex;
		std::shared_ptr<IFavorite> fav;
		tscrypto::tsCryptoString name;
		GUID id = GUID_NULL;
		LRESULT idx = -1;

		// Verify that the user wishes to eliminate any previously displayed access groups.
		name.resize(512);

		if (!_connector)
			return FALSE;
		// First see if we are truly setting a favorite

		favIndex = (int)SendMessage(_FavoriteCombo, CB_GETCURSEL, 0, 0);
		if (0 >= favIndex) {
			SendMessage(_FavoriteCombo, CB_SETCURSEL, (WPARAM)0, 0);
			_CurFavIndex = 0;
			UpdateDialogControls();
			EnableDisableOK();
			return FALSE;
		}
		// See if the favorite has changed
		if (_CurFavIndex == favIndex)
		{
			EnableDisableOK();
			return FALSE;
		}

		idx = SendMessage(_FavoriteCombo, CB_GETITEMDATA, favIndex, 0);
		if (idx >= 0 && idx < (LRESULT)_guidMap.size())
		{
			id = _guidMap[idx];
		}

		size_t accessGroupCount = 0;
		{
			std::shared_ptr<ICmsHeaderExtension> ext;
			std::shared_ptr<ICmsHeaderAccessGroupExtension> groupList;

			if (!_header || !_header->GetProtectedExtensionByOID(tscrypto::tsCryptoData(id_TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), ext) ||
				!(groupList = std::dynamic_pointer_cast<ICmsHeaderAccessGroupExtension>(ext)))
			{
			}
			else
				accessGroupCount = groupList->GetAccessGroupCount();
		}
		if (SendMessage(_GroupCtrl, LVM_GETITEMCOUNT, 0, 0) > 0)
		{
			LVITEMA item;

			memset(&item, 0, sizeof(item));
			item.mask = LVIF_TEXT;
			item.pszText = name.rawData();
			item.cchTextMax = (int)name.size();
			SendMessageA(_GroupCtrl, LVM_GETITEMTEXTA, 0, (LPARAM)&item);
			name.resize(tsStrLen(name.c_str()));
		}

		// TODO:  Reenable the last term once we implement PKI
		if (name.size() > 0 && tsStrCmp(name.c_str(), AS_SEL_DOM_STR) != 0 && accessGroupCount > 0)// || mySelectedCertVector.size() > 0)
		{
			//UINT nResponse = ::MessageBox(_hDlg, "Selecting a favorite will cause all current Attribute and certificate selections to be lost.\n\n Do you wish to continue?", "Warning", MB_YESNO | MB_ICONINFORMATION);
			UINT nResponse = ::MessageBoxA(_hDlg, "Selecting a favorite will cause all current Attribute selections to be lost.\n\n Do you wish to continue?", "Warning", MB_YESNO | MB_ICONINFORMATION);

			if (nResponse != IDYES)
			{
				/* Reset the favorite index before returning. */
				SendMessage(_FavoriteCombo, CB_SETCURSEL, _CurFavIndex, 0);
				return FALSE;
			}
		}

		// unset the stored Favorite
		_favorite.reset();

		/* Set the current favorite index to keep track of previous selections. */
		_CurFavIndex = favIndex;

		// deselect the favorite in case we can't switch to it
		// we will reselect it at the end if possible
		SendMessage(_FavoriteCombo, CB_SETCURSEL, (WPARAM)0, 0);
		EnableDisableOK();

		// get rid of the old CryptoGroup and token
		//    myActiveToken = NULL;
		_ActiveCryptoGroup = nullptr;
		ClearAccessGroups();

		// get a pointer to the favorite
		fav = _connector->favorite(id);
		if (!fav)
		{
			if (_initialized)
				MessageBoxA(_hDlg, "Error! Invalid favorite pointer in selection.", "Error", MB_ICONHAND | MB_OK);
			return FALSE;
		}

		// empty out the old attribute and cert lists
		/* Must loop through and delete all access groups in the grouplist control that we have stored
		previously. */
		SendMessage(_GroupCtrl, LVM_DELETEALLITEMS, 0, 0);
		AddGroupText(AS_SEL_DOM_STR);
		EnableWindow(_GroupCtrl, FALSE);

		// TODO:  Implement when PKI supported
		//    mySelectedCertVector.clear();
		//SendMessage(_CryptoGroupCombo, CB_RESETCONTENT, 0, 0);
		//SendMessage(_CryptoGroupCombo, CB_SETCURSEL, (WPARAM)(-1), 0);

		UpdateDialogControls();
		EnableDisableOK();

		//Check if Token not present in the Slot
		UINT ind = (UINT)SendMessage(_TokenCombo, CB_GETCURSEL, 0, 0);

		if (ind != (UINT)-1)
		{
			if (!HasSession())
			{
				// TODO:  I think something is needed here
				//CryptoGroupPressLogin();
			}
		}

		std::shared_ptr<ICmsHeader> newHeader;
		tscrypto::tsCryptoData headData(fav->headerData());

		if (!(newHeader = ::TopServiceLocator()->get_instance<ICmsHeader>("/CmsHeader")))
		{
			MessageBoxA(_hDlg, "Unable to edit... Unable to create a CMS Header.", "Error", MB_ICONHAND | MB_OK);
			return FALSE;
		}

		if (!newHeader->IsProbableHeader(headData.c_str(), headData.size()))
		{
			MessageBoxA(_hDlg, "The selected favorite does not contain a valid CMS header.", "Error", MB_ICONHAND | MB_OK);
			return FALSE;
		}

		//BOOL bContinue ;
		BOOL bLoaded = FALSE;
		//Load the cryptogroup for Token selected, login and load the attributes
		//Then check the Favorites cryptogroup and attributes with that of the Token
		//if not matched, give the user the opportunity to select another Token
		do
		{
			if (!HasSession() || (bLoaded = LoadFavoriteForToken(fav, newHeader)) == 0)    // if the favorites cryptogroup and attributes do not match with Token's
			{
				UINT nResponse = IDYES;

				if (HasSession())
				{
					nResponse = ::MessageBoxA(_hDlg, "The Token does not contain the proper CryptoGroup or Attributes needed for the Favorite.\nDo you want to select another Token? ", "Warning", MB_YESNO | MB_ICONQUESTION);
				}
				if (nResponse == IDYES)
				{
					std::shared_ptr<ICmsHeaderCryptoGroup> hCG;
					std::shared_ptr<ICmsHeader> head7;
					std::shared_ptr<IKeyVEILSession> sess;

					if (!!(head7 = ::TopServiceLocator()->try_get_instance<ICmsHeader>("/CmsHeader")) && head7->FromBytes(fav->headerData()))
					{
						if (head7->GetCryptoGroupCount() == 1 && (head7->GetCryptoGroup(0, hCG)))
						{
							GUID enterpriseOid = GUID_NULL;
							std::shared_ptr<ITokenSelector> tokSel = ::TopServiceLocator()->get_instance<ITokenSelector>("/WinAPI/TokenSelector");

							head7->GetEnterpriseGuid(enterpriseOid);

							if (tokSel->Start(_connector, enterpriseOid, "Select a token for the favorite", (XP_WINDOW)_hDlg) && tokSel->DisplayModal() == IDOK && !!(sess = tokSel->Session()))
							{
								int tokIndex = -1;

								if (sess->GetProfile()->exists_SerialNumber())
									tokIndex = FindTokenOnComboBox(*sess->GetProfile()->get_SerialNumber());

								if (tokIndex >= 0)
								{
									SendMessage(_TokenCombo, CB_SETCURSEL, tokIndex, 0);
									//if (!!_session)
									//	_session->Close();
									Session(sess);
								}
								else
								{
									return FALSE;
								}
							}
							else
								return FALSE;
						}
						else
							return FALSE;
					}
					else
						return FALSE;
				}
				else     //user does not want to select another Token
				{
					return FALSE;
				}
			}
		} while (!bLoaded);

		// TODO:  Implement me
		//    // set this new favorite as the "default"
		//    if (myRememberFavorite)
		//        myFavs.SetDefaultFavorite(fav->favName);

		// remember the name in case we have to build an audience
		_favorite = fav;

		SendMessage(_FavoriteCombo, CB_SETCURSEL, favIndex, 0);
		_CurFavIndex = favIndex;
		EnableDisableOK();

		RebuildAccessGroupList();
		return FALSE;
	}

	//	BOOL populateCryptoGroupList()
	//	{
	//		DWORD index = 0;
	//		//    CK_RV rc = 0;
	//		//    TS_FIEFDOM_POLICY_PTR pFiefPol = NULL;
	//
	//		/* If no token is selected, we need to get the first one in the list. */
	//		//if (!_session)
	//		//{
	//			//if (SendMessage(_TokenCombo, CB_GETCURSEL, 0, 0) < 0 && SendMessage(_TokenCombo, CB_GETCOUNT, 0, 0) > 0)
	//			//{
	//			//	SendMessage(_TokenCombo, CB_SETCURSEL, 0, 0);
	//			//}
	//			//if (SendMessage(_TokenCombo, CB_GETCURSEL, 0, 0) >= 0)
	//			//{
	//			//	OnChangeTokenByControl();
	//			//}
	//		//}
	//
	//		if (!_session)
	//		{
	//			MessageBoxA(_hDlg, "Please select a token before attempting to select the crypto group.", "Warning", MB_ICONHAND | MB_OK);
	//			return FALSE;
	//		}
	//
	//		//if (!_session->isValid())
	//		//{
	//		//	MessageBoxA(_hDlg, "The selected token is not available for use at this time.  Please select a different token.", "Warning", MB_ICONHAND | MB_OK);
	//		//	return FALSE;
	//		//}
	//
	//		/* Return if login fails. */
	//		if (FALSE == CheckLogin())
	//		{
	//			return FALSE;
	//		}
	//
	//		/* Populate Crypto Group combo box with list of CryptoGroups available on this token that aren't expired, etc. */
	//		if (!_ActiveCryptoGroup)
	//		{
	//			std::shared_ptr<Asn1::CTS::CryptoGroup> cg;
	//			std::shared_ptr<Asn1::CTS::Profile> profile = _session->GetProfile();
	//			size_t cgCount;
	//
	//			if (!profile || !profile->exists_cryptoGroupList())
	//			{
	//				return FALSE;
	//			}
	//
	//			// TODO:  Not checking policy at this time.  Implement later
	//#if 0
	//			tscrypto::tsCryptoString ckmStr;
	//			tscrypto::tsCryptoData domPolStr;
	//			_CryptoGroupCombo.ResetContent();
	//			myTokenDomVector = myActiveSession->listFiefdomObjects();
	//			for (CKMVector<CKMO_FIEFDOM>::iterator iter = myTokenDomVector->begin(); iter != myTokenDomVector->end(); iter++)
	//			{
	//				/* If the fiefdom is time invalid and the fiefdom policy indicates we should
	//				care, dont display the fiefdom in the list.  Otherwise, add da sucka. */
	//				domPolStr = iter->getPolicy();
	//				pFiefPol = (TS_FIEFDOM_POLICY_PTR)domPolStr.data();
	//				rc = iCheckFiefdomPolicy(pFiefPol);
	//				if (rc == CKR_FIEFDOM_ISSUED_IN_FUTURE || rc == CKR_FIEFDOM_EXPIRED)
	//				{
	//					/* If the fiefdom policy indicates that a "negative" action should take place,
	//					don't list the fiefdom. */
	//					if (pFiefPol->expireAction == TS_ACTION_FAIL ||
	//						pFiefPol->expireAction == TS_ACTION_DESTROY)
	//					{
	//						continue;
	//					}
	//				}
	//
	//				/* If the above if statement didn't skip this code, that means the fiefdom was time valid or
	//				the TS_ACTION was TS_ACTION_NONE. */
	//				ckmStr = iter->getLabel();
	//				index = _CryptoGroupCombo.AddString(ckmStr.c_str());
	//				_CryptoGroupCombo.SetItemDataPtr(index, &*iter);
	//			}
	//#endif
	//			if (profile->exists_cryptoGroupList())
	//			{
	//				cgCount = profile->get_cryptoGroupList()->size();
	//
	//				SendMessage(_CryptoGroupCombo, CB_RESETCONTENT, 0, 0);
	//				for (index = 0; index < cgCount; index++)
	//				{
	//					cg.reset();
	//					cg = profile->get_cryptoGroupList()->get_ptr_at(index);
	//					if (!!cg)
	//					{
	//						tscrypto::tsCryptoString name;
	//
	//						// TODO:  Add expiration checking here
	//
	//						name = cg->get_Name();
	//						int item = (int)SendMessage(_CryptoGroupCombo, CB_ADDSTRING, 0, (LPARAM)name.c_str());
	//						if (item != -1)
	//						{
	//							SendMessage(_CryptoGroupCombo, CB_SETITEMDATA, item, index);
	//						}
	//					}
	//				}
	//			}
	//			SendMessage(_CryptoGroupCombo, CB_SETCURSEL, 0, 0);
	//			OnChangeCryptoGroup();
	//		}
	//
	//		return FALSE;
	//	}

	void ClearAccessGroups()
	{
		/* Clear group control box and all ag lists. */
		if (!!_header)
		{
			_header->RemoveExtension(tscrypto::tsCryptoData(id_TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID));
			_header->RemoveExtension(tscrypto::tsCryptoData(id_TECSEC_CKMHEADER_V7_ATTRIBUTELIST_EXT_OID, tscrypto::tsCryptoData::OID));
		}

		SendMessage(_GroupCtrl, LVM_DELETEALLITEMS, 0, 0);
	}

	tscrypto::tsCryptoString BuildAttrsLine(std::shared_ptr<ICmsHeaderAttributeGroup> attrs)
	{
		int index, idx;
		int count;
        tscrypto::tsCryptoData id;
		Asn1::CTS::_POD_Attribute* attr = nullptr;
		std::shared_ptr<ICmsHeaderAttribute> headerAttr;
		std::shared_ptr<ICmsHeaderAttributeListExtension> attrList;
		std::shared_ptr<ICmsHeaderExtension> ext;
		tscrypto::tsCryptoString name;
		tscrypto::tsCryptoString list;

		if (!_ActiveCryptoGroup || !_header || !_header->GetProtectedExtensionByOID(tscrypto::tsCryptoData(id_TECSEC_CKMHEADER_V7_ATTRIBUTELIST_EXT_OID, tscrypto::tsCryptoData::OID), ext) ||
			!(attrList = std::dynamic_pointer_cast<ICmsHeaderAttributeListExtension>(ext)))
		{
			return "";
		}
		ext.reset();
		count = (int)attrs->GetAttributeCount();
		for (index = 0; index < count; index++)
		{
			attr = nullptr;
			idx = attrs->GetAttributeIndex(index);
			headerAttr.reset();
			if (attrList->GetAttribute(idx, headerAttr))
			{
				id = headerAttr->GetAttributeId();

				attr = _ActiveCryptoGroup->get_AttributeById(id);
				if (!!attr)
				{
					name = attr->get_Name();
					if (name.size() == 0)
					{
						name.Format("<attr %s>", id.ToHexString().c_str());
					}
				}
				else
				{
					name.Format("<attr %s>", id.ToHexString().c_str());
				}
				if (list.size() > 0)
				{
					list += "; ";
				}
				list += name;
			}
		}

		return list;
	}

	//tscrypto::tsCryptoString BuildPinLine(ICKM7HeaderPinGroup *pin)
	//{
	//	return "PASSWORD for " + pin->GetDescription();
	//}

	BOOL RebuildAccessGroupList()
	{
		tscrypto::tsCryptoString line;

		if (!!_header)
		{
			std::shared_ptr<ICmsHeaderAccessGroup>   andGroup;
			std::shared_ptr<ICmsHeaderAttributeGroup>  attrGroup;
			//			std::shared_ptr<ICmsHeaderPinGroup>  pinGroup;
			int accessGroupCount;
			int sel;
			int selPeople;
			int index;

			sel = (int)SendMessage(_GroupCtrl, LVM_GETNEXTITEM, (WPARAM)-1, MAKELPARAM(LVNI_SELECTED, 0));
			selPeople = (int)SendMessage(_RichCertList, LVM_GETNEXTITEM, (WPARAM)-1, MAKELPARAM(LVNI_SELECTED, 0));
			SendMessage(_GroupCtrl, LVM_DELETEALLITEMS, 0, 0);
			SendMessage(_RichCertList, LVM_DELETEALLITEMS, 0, 0);

			std::shared_ptr<ICmsHeaderExtension> ext;
			std::shared_ptr<ICmsHeaderAccessGroupExtension> extGroup;
			if (!_header->GetProtectedExtensionByOID(tscrypto::tsCryptoData(id_TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), ext))
			{
				_header->AddProtectedExtension(tscrypto::tsCryptoData(id_TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), true, ext);
			}

			if (!ext || !(extGroup = std::dynamic_pointer_cast<ICmsHeaderAccessGroupExtension>(ext)))
			{
				return TRUE;
			}
			ext.reset();

			accessGroupCount = (int)extGroup->GetAccessGroupCount();
			for (index = 0; index < accessGroupCount; index++)
			{
				andGroup.reset();
				attrGroup.reset();
				//pinGroup.reset();

				if ((extGroup->GetAccessGroup(index, andGroup)))
				{
					if (andGroup->GetAndGroupType() == ag_Attrs && !!(attrGroup = std::dynamic_pointer_cast<ICmsHeaderAttributeGroup>(andGroup)))
					{
						line = BuildAttrsLine(attrGroup);
						AddGroupText(line.c_str());
					}
					//else if (andGroup->GetAndGroupType() == ag_Pin &&
					//	SUCCEEDED(andGroup->QueryInterface(&pinGroup)))
					//{
					//	line = BuildPinLine(pinGroup);
					//	AddCertText(line.c_str());
					//}
				}
			}

			if (sel < 0 || sel >= SendMessage(_GroupCtrl, LVM_GETITEMCOUNT, 0, 0))
			{
				sel = (int)SendMessage(_GroupCtrl, LVM_GETITEMCOUNT, 0, 0) - 1;
			}
			SetItemSelected(sel);
			if (selPeople < 0 || selPeople >= SendMessage(_RichCertList, LVM_GETITEMCOUNT, 0, 0))
			{
				selPeople = (int)SendMessage(_RichCertList, LVM_GETITEMCOUNT, 0, 0) - 1;
			}
			SetPersonSelected(selPeople);
			EnableWindow(_GroupCtrl, (accessGroupCount > 0));
		}
		return TRUE;
	}

	void SetItemSelected(int index)
	{
		LVITEM item;

		memset(&item, 0, sizeof(item));
		item.mask = LVIF_STATE;
		item.stateMask = LVNI_SELECTED;
		item.state = LVNI_SELECTED;
		item.iItem = index;
		SendMessage(_GroupCtrl, LVM_SETITEMSTATE, index, (LPARAM)&item);
	}

	void SetPersonSelected(int index)
	{
		LVITEM item;

		memset(&item, 0, sizeof(item));
		item.mask = LVIF_STATE;
		item.stateMask = LVNI_SELECTED;
		item.state = LVNI_SELECTED;
		item.iItem = index;
		SendMessage(_RichCertList, LVM_SETITEMSTATE, index, (LPARAM)&item);
	}

	void AddGroupText(const char *text)
	{
		LVITEMA item;

		memset(&item, 0, sizeof(item));
		item.mask = LVIF_TEXT;
		item.pszText = (char *)text;
		item.cchTextMax = (int)tsStrLen(text) + 1;
		item.iItem = 0x7FFFFFFF;

		SendMessageA(_GroupCtrl, LVM_INSERTITEMA, 0, (LPARAM)&item);
	}

	void AddCertText(const char *text)
	{
		LVITEMA item;

		memset(&item, 0, sizeof(item));
		item.mask = LVIF_TEXT;
		item.pszText = (char *)text;
		item.cchTextMax = (int)tsStrLen(text) + 1;
		item.iItem = 0x7FFFFFFF;

		SendMessageA(_RichCertList, LVM_INSERTITEMA, 0, (LPARAM)&item);
	}

	BOOL QueryAndClearAccessGroups()
	{
		if (SendMessage(_GroupCtrl, LVM_GETITEMCOUNT, 0, 0) > 0)
		{
			char name[512];
			LVITEMA item;

			memset(&item, 0, sizeof(item));
			item.mask = LVIF_TEXT;
			item.pszText = name;
			item.cchTextMax = sizeof(name) / sizeof(char);
			name[0] = 0;

			SendMessageA(_GroupCtrl, LVM_GETITEMTEXTA, 0, (LPARAM)&item);
			/* If there is one item in the list and it is the text string AS_SEL_DOM_STR, don't
			pop up the warning message. */
			if (SendMessage(_GroupCtrl, LVM_GETITEMCOUNT, 0, 0) != 1 || tsStrCmp(name, AS_SEL_DOM_STR) != 0)
			{
				UINT nResponse = ::MessageBoxA(_hDlg, "Changing Tokens will cause all current Attribute selections to be lost.\n\n Do you wish to continue?", "Warning", MB_YESNO | MB_ICONINFORMATION);

				if (nResponse != IDYES)
				{
					// Restore the value to the prior selection
					SendMessage(_TokenCombo, CB_SETCURSEL, (WPARAM)_LastTokenSelection, 0);
					return FALSE;
				}
			}

			ClearAccessGroups();

			AddGroupText(AS_SEL_DOM_STR);
			EnableWindow(_GroupCtrl, FALSE);
		}
		return TRUE;
	}

    intptr_t OnChangeTokenByControl()
	{
		// if the programmer has specified an initial token, and a reason
		// not to change it, we won't allow the user to switch to a new token
		//if (myInitialToken != NULL && myNoChangeTokenReason.GetLength()) {
		if (HasSession() && Session()->IsValid() && !!_connector)
		{
			int tokindex = 0;
			std::shared_ptr<IKeyVEILSession> tempSession;
			//        CKMToken* pTempToken = NULL;

			// first get the user's selection
			tokindex = (int)SendMessage(_TokenCombo, CB_GETCURSEL, 0, 0);
			if (-1 != tokindex)
			{
				LRESULT index = SendMessage(_TokenCombo, CB_GETITEMDATA, tokindex, 0);

				if (index < 0 || index >= (LRESULT)_tokenSerialNumbers.size())
				{
				}
				else
				{
					tscrypto::tsCryptoData serialNumber = _tokenSerialNumbers[index];
					std::shared_ptr<IToken> token = _connector->token(serialNumber);

					if (!token)
					{
						ClearAccessGroups();
						AddGroupText(AS_SEL_DOM_STR);

						EnableWindow(_GroupCtrl, FALSE);

						EnableDisableOK();

						//SendMessage(_CryptoGroupCombo, CB_RESETCONTENT, 0, 0);
						//SendMessage(_CryptoGroupCombo, CB_ADDSTRING, 0, (LPARAM)AS_SEL_DOM_STR);
						//SendMessage(_CryptoGroupCombo, CB_ADDSTRING, 0, (LPARAM)AS_SEL_DOM_STR);
						//SendMessage(_CryptoGroupCombo, CB_SETCURSEL, 0, 0);

						_ActiveCryptoGroup = nullptr;

						//if (!!_session)
						//	_session->Close();
						Session(nullptr);
						EnableWindow(GetDlgItem(_hDlg, IDC_TOKEN_LOGIN), FALSE);
						UpdateDialogControls();
						SetFocus(_TokenCombo);
						return FALSE;
					}
					else
					{
						tempSession = token->openSession();
					}
				}
			}

			//if (!!tempSession /*&& !tempSession->isValid()*/)
			//{
			//	MessageBox(_hDlg, "The selected token is not valid.", "Error", MB_OK);
			//	return FALSE;
			//}

			// if the selection has not changed, return
			if (HasSession() && Session()->IsValid() && HasProfile() && !!tempSession->GetProfile() && tempSession->GetProfile()->get_SerialNumber() == GetProfile()->get_SerialNumber())
			{
				return FALSE;
			}

			// Let the user know that any currently selected attributes will
			// be lost by selecting a new token.
			if (!QueryAndClearAccessGroups())
			{
				return FALSE;
			}
		}

		if (!ChangeToken())
			return FALSE;

		//if (SendMessage(_CryptoGroupCombo, CB_GETCOUNT, 0, 0) > 1)
		//{
		//	//_CryptoGroupCombo.SetFocus();
		//	//_CryptoGroupCombo.ShowDropDown();
		//	// added because a bug in MFC sometimes hides the cursor
		//	SetCursor(LoadCursor(NULL, IDC_ARROW));
		//}
		//else
		//{
		//	SendMessage(_CryptoGroupCombo, CB_SETCURSEL, 0, 0);
		//}

		UpdateDialogControls();
		return FALSE;
	}

	//
	// when called by other functions we don't auto-select a CryptoGroup
	//
	BOOL ChangeToken()
	{
		int index;

		// return false if nothing is selected
		index = (int)SendMessage(_TokenCombo, CB_GETCURSEL, 0, 0);
		if (-1 == index || !_connector) {
			return FALSE;
		}

		// empty the Favorite combo box and free any memory being used
		SendMessage(_FavoriteCombo, CB_SETCURSEL, (WPARAM)(0), 0);
		_favorite.reset();
		_CurFavIndex = 0;

		//SendMessage(_CryptoGroupCombo, CB_RESETCONTENT, 0, 0);

		if (!!_header)
		{
			_header->RemoveExtension(tscrypto::tsCryptoData(id_TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID));
			_header->RemoveExtension(tscrypto::tsCryptoData(id_TECSEC_CKMHEADER_V7_ATTRIBUTELIST_EXT_OID, tscrypto::tsCryptoData::OID));
		}

		/* Don't forget to clean up any existing access groups that are saved in the _GroupCtrl. */
		SendMessage(_GroupCtrl, LVM_DELETEALLITEMS, 0, 0);
		AddGroupText(AS_SEL_DOM_STR);
		EnableWindow(_GroupCtrl, FALSE);

		EnableDisableOK();

		//SendMessage(_CryptoGroupCombo, CB_ADDSTRING, 0, (LPARAM)AS_SEL_DOM_STR);
		//SendMessage(_CryptoGroupCombo, CB_ADDSTRING, 0, (LPARAM)AS_SEL_DOM_STR);
		//SendMessage(_CryptoGroupCombo, CB_SETCURSEL, 0, 0);

		_ActiveCryptoGroup = nullptr;

		//if (!!_session)
		//	_session->Close();
		Session(nullptr);
		_header.reset();

		LRESULT idx = SendMessage(_TokenCombo, CB_GETITEMDATA, index, 0);
		std::shared_ptr<IToken> tok;

		if (idx >= 0 && idx < (LRESULT)_tokenSerialNumbers.size())
		{
			tok = _connector->token(_tokenSerialNumbers[idx]);
		}
		if (!tok)
		{
			char name[512];

			SendMessage(_TokenCombo, CB_GETLBTEXT, index, (LPARAM)name);
			tsStrCat(name, sizeof(name), "  Unable to change Token.");
			MessageBoxA(_hDlg, name, "Error", MB_OK);
			return FALSE;
		}
		Session(tok->openSession());
		if (!HasSession())
		{
			char name[512];

			SendMessage(_TokenCombo, CB_GETLBTEXT, index, (LPARAM)name);
			tsStrCat(name, sizeof(name), "  Unable to change Token.");
			MessageBoxA(_hDlg, name, "Error", MB_OK);
			return FALSE;
		}

		EnableWindow(GetDlgItem(_hDlg, IDC_TOKEN_LOGIN), HasSession() && (!Session()->IsValid() || !Session()->IsLoggedIn()));

		if (HasSession() && Session()->IsValid() && Session()->IsLoggedIn())
		{
			SendMessage(_GroupCtrl, LVM_DELETEALLITEMS, 0, 0);
			EnableWindow(_GroupCtrl, TRUE);

            tscrypto::tsCryptoData cgID = GetProfile()->get_EnterpriseCryptoGroup();

			_ActiveCryptoGroup = GetCGbyGuid(cgID);
			//if ( !header )
			//{
			_header = ::TopServiceLocator()->try_get_instance<ICmsHeader>("/CmsHeader");
			if (!_header)
			{
				MessageBoxA(_hDlg, "OnChangeCryptoGroup: Unable to create a CKM Header.", "Error", MB_ICONHAND | MB_OK);
				return FALSE;
			}
			//	}

			if (!!_header)
			{
				int domIndex;
				GUID enterpriseGuid = GUID_NULL;
				GUID memberGuid = GUID_NULL;

				_header->Clear();
				if (HasProfile())
				{
					enterpriseGuid = GetProfile()->get_EnterpriseId();
					memberGuid = GetProfile()->get_MemberId();
				}
				_header->SetEnterpriseGuid(enterpriseGuid);
				_header->SetCreatorGuid(memberGuid);
				if ((_header->AddCryptoGroup(cgID, &domIndex)))
				{
					//			hFief->SetUniqueNumber(1);
				}
			}

		}
		EnableDisableOK();
		UpdateDialogControls();
		//if (!!_session && _session->IsLoggedIn())
		//{
		//	// We can select the first CryptoGroup here
		//	populateCryptoGroupList();
		//}

		return TRUE;
	}

	int CheckLogin()
	{
		if (!HasSession())
			return FALSE;

		if (Session()->IsLoggedIn() && Session()->IsValid() && HasProfile())
		{
			if (!_ActiveCryptoGroup)
			{
                tscrypto::tsCryptoData cgID = GetProfile()->get_EnterpriseCryptoGroup();

				_ActiveCryptoGroup = GetCGbyGuid(cgID);
			}
			return !!_ActiveCryptoGroup;
		}

		std::shared_ptr<ITokenLogin> login = ::TopServiceLocator()->try_get_instance<ITokenLogin>("/WinAPI/TokenLogIn");;

		_ActiveCryptoGroup = nullptr;
		if (!!login)
		{
			if (!login->Start(Session(), (XP_WINDOW)_hDlg) || login->DisplayModal() != IDOK)
				return FALSE;

            tscrypto::tsCryptoData cgID = GetProfile()->get_EnterpriseCryptoGroup();

			_ActiveCryptoGroup = GetCGbyGuid(cgID);
			//if ( !header )
			//{
			_header = ::TopServiceLocator()->try_get_instance<ICmsHeader>("/CmsHeader");
			if (!_header)
			{
				MessageBoxA(_hDlg, "OnChangeCryptoGroup: Unable to create a CKM Header.", "Error", MB_ICONHAND | MB_OK);
				return FALSE;
			}
			//	}

			if (!!_header)
			{
				int domIndex;
				GUID enterpriseGuid = GUID_NULL;
				GUID memberGuid = GUID_NULL;

				_header->Clear();
				if (HasProfile())
				{
					enterpriseGuid = GetProfile()->get_EnterpriseId();
					memberGuid = GetProfile()->get_MemberId();
				}
				_header->SetEnterpriseGuid(enterpriseGuid);
				_header->SetCreatorGuid(memberGuid);
				if ((_header->AddCryptoGroup(cgID, &domIndex)))
				{
					//			hFief->SetUniqueNumber(1);
				}
			}
		}
		else
			return FALSE;
		return TRUE;
	}

	//	intptr_t OnChangeCryptoGroup()
	//	{
	//		int index;
	//		std::shared_ptr<Asn1::CTS::CryptoGroup> tempCryptoGroup;
	//
	//		// return if no CryptoGroup is selected
	//		index = (int)SendMessage(_CryptoGroupCombo, CB_GETCURSEL, 0, 0);
	//		if (-1 == index)
	//		{
	//			return FALSE;
	//		}
	//
	//		if (!_session)
	//		{
	//			MessageBoxA(_hDlg, "Invalid Token! Unable to change CryptoGroups.", "Error", MB_ICONHAND | MB_OK);
	//			return FALSE;
	//		}
	//
	//		// get the selected CryptoGroup object
	//		int itemIndex = (int)SendMessage(_CryptoGroupCombo, CB_GETITEMDATA, index, 0);
	//		if (itemIndex < 0 || !_session->GetProfile()->exists_cryptoGroupList() || itemIndex >= (int)_session->GetProfile()->get_cryptoGroupList()->size() || 
	//			!(tempCryptoGroup = _session->GetProfile()->get_cryptoGroupList()->get_ptr_at(itemIndex)))
	//		{
	//			//        MessageBox(_hDlg, "Invalid CryptoGroup object! Unable to change Crypto Groups.", "Error", MB_ICONHAND | MB_OK);
	//			return FALSE;
	//		}
	//
	//		// If the cryptogroup has not actually changed, do nothing.
	//		if (!!_ActiveCryptoGroup && (_ActiveCryptoGroup->get_Id() == tempCryptoGroup->get_Id()))
	//		{
	//			return FALSE;
	//		}
	//
	//		/* Need to post warning telling user that the selected AGs will be lost if the CryptoGroup is changed.
	//		Only do this if AGs are currently selected.  If the user presses cancel, do nothing, otherwise
	//		post login window and continue with clearing of AG box and populating the CryptoGroup list. */
	//		if (!QueryAndClearAccessGroups())
	//		{
	//			return FALSE;
	//		}
	//
	//		// clear the group list
	//		ClearAccessGroups();
	//		EnableWindow(_GroupCtrl, FALSE);
	//
	//		// return if no token is selected
	//		if (!_session)
	//			return FALSE;
	//
	//		/* Verify we are logged in or log in to the currently selected token. */
	//		if (FALSE == CheckLogin())
	//		{
	//			//myActiveToken = NULL;
	//			AddGroupText(AS_SEL_DOM_STR);
	//			return FALSE;
	//		}
	//
	//		// store the CryptoGroup object
	//		_ActiveCryptoGroup.reset();
	//
	//		_ActiveCryptoGroup = tempCryptoGroup;
	//
	//		//
	//		// At this point we need to update the header CryptoGroup and enterprise information.
	//		//
	//		GUID cryptoGroupGuid = { 0, };
	//		GUID enterpriseGuid = { 0, };
	//		GUID memberGuid = { 0, };
	//		std::shared_ptr<Asn1::CTS::Profile> profile;
	//
	//		//if ( !header )
	//		//{
	//		_header = ::TopServiceLocator()->try_get_instance<ICmsHeader>("/CmsHeader");
	//		if (!_header)
	//		{
	//			MessageBoxA(_hDlg, "OnChangeCryptoGroup: Unable to create a CKM Header.", "Error", MB_ICONHAND | MB_OK);
	//			return FALSE;
	//		}
	//		//	}
	//
	//		if (!!_header)
	//		{
	//			int domIndex;
	//
	//			_header->Clear();
	//			profile = _session->GetProfile();
	//			if (!!profile)
	//			{
	//				enterpriseGuid = profile->get_EnterpriseId();
	//				memberGuid = profile->get_MemberId();
	//			}
	//			cryptoGroupGuid = _ActiveCryptoGroup->get_Id();
	//			_header->SetEnterpriseGuid(enterpriseGuid);
	//			_header->SetCreatorGuid(memberGuid);
	//			if ((_header->AddCryptoGroup(cryptoGroupGuid, &domIndex)))
	//			{
	//				//			hFief->SetUniqueNumber(1);
	//			}
	//		}
	//		// TODO:  Saved for when we need to filter attributes
	//#if 0
	//		tscrypto::tsCryptoData domPolStr, attrPolStr;
	//		CK_RV rc;
	//		TS_FIEFDOM_POLICY_PTR pFiefPol = NULL;
	//
	//		/* We need the fiefdom policy in case an attribute is expired.  The fie policy will tell us
	//		whether we should list it anyway. */
	//		domPolStr = _ActiveCryptoGroup->getPolicy();
	//		pFiefPol = (TS_FIEFDOM_POLICY_PTR)domPolStr.data();
	//
	//		myTokenAttrVector = new CKMVector<CKMO_Attribute>;
	//		for (CKMVector<CKMO_Attribute>::iterator iter = pTempAttrVect->begin(); iter != pTempAttrVect->end(); iter++)
	//		{
	//			/* Get the attributes policy.  This includes information on expire and issue dates. Then
	//			call the check attr function which will validate the dates. */
	//			attrPolStr = iter->getPolicy();
	//			rc = iCheckAttributePolicy(pFiefPol, (TS_ATTRIBUTE_POLICY_PTR)attrPolStr.data());
	//
	//			if (rc == CKR_ATTR_ISSUED_IN_FUTURE || rc == CKR_ATTR_EXPIRED)
	//			{
	//				/* If the fiefdom policy indicates that a "negative" action should take place,
	//				don't list the attribute. */
	//				if (pFiefPol->expireAction == TS_ACTION_FAIL ||
	//					pFiefPol->expireAction == TS_ACTION_DESTROY)
	//				{
	//					continue;
	//				}
	//			}
	//
	//			/* If the above if statement didn't skip this code, that means the fiefdom was time valid or
	//			the TS_ACTION was TS_ACTION_NONE. Add the attribute to the vector. */
	//			myTokenAttrVector->push_back(*iter);
	//		}
	//		delete pTempAttrVect;
	//		pTempAttrVect = NULL;
	//
	//		// set the categories so the tool tips work
	//		_GroupCtrl.SetCatList(myTokenCatVector);
	//#endif
	//
	//		// unset any selected favorite
	//		SendMessage(_FavoriteCombo, CB_SETCURSEL, (WPARAM)(0), 0);
	//		_favorite.reset();
	//
	//		/* If still don't have a cryptoGroup, put "Select a CryptoGroup..." back into AG list box. */
	//		if (!_ActiveCryptoGroup)
	//		{
	//			AddGroupText(AS_SEL_DOM_STR);
	//		}
	//		else
	//		{
	//			EnableWindow(_GroupCtrl, TRUE);
	//		}
	//
	//		UpdateDialogControls();
	//		return FALSE;
	//	}
intptr_t OnChangeRichEdit()
	{
		UpdateDialogControls();
		return FALSE;
	}

intptr_t OnChangeGroupList()
	{
		UpdateDialogControls();
		return FALSE;
	}

intptr_t OnDblclkGrouplist()
	{
		OnGroupEdit();
		return FALSE;
	}

intptr_t OnDblclkCertList()
	{
		// TODO:  Implement me
		return FALSE;
	}
	void UpdateDialogControls()
	{
		int index;


		EnableWindow(GetDlgItem(_hDlg, IDC_GROUPADD), TRUE);
		EnableWindow(GetDlgItem(_hDlg, IDC_PEOPLE), _PKIHidden ? FALSE : TRUE);
		// first make sure a cryptoGroup is selected
		if (!_ActiveCryptoGroup)
		{
			EnableWindow(GetDlgItem(_hDlg, IDC_GROUPADD), FALSE);
			EnableWindow(GetDlgItem(_hDlg, IDC_GROUPDELETE), FALSE);
			EnableWindow(GetDlgItem(_hDlg, IDC_GROUPEDIT), FALSE);
		}
		else
		{
			// now see if a group is selected
			index = (int)SendMessage(_GroupCtrl, LVM_GETNEXTITEM, (WPARAM)-1, MAKELPARAM(LVNI_SELECTED, 0));
			if (-1 == index)
			{
				EnableWindow(GetDlgItem(_hDlg, IDC_GROUPDELETE), FALSE);
				EnableWindow(GetDlgItem(_hDlg, IDC_GROUPEDIT), FALSE);
			}
			else
			{
				EnableWindow(GetDlgItem(_hDlg, IDC_GROUPDELETE), TRUE);
				EnableWindow(GetDlgItem(_hDlg, IDC_GROUPEDIT), TRUE);
			}
		}
		if (_CurFavIndex == 0)
			SetWindowTextA(GetDlgItem(_hDlg, IDC_CREATE_FAVORITE), "Create &Favorite");
		else
			SetWindowTextA(GetDlgItem(_hDlg, IDC_CREATE_FAVORITE), "Update &Favorite");

		index = (int)SendMessage(_RichCertList, LVM_GETNEXTITEM, (WPARAM)-1, MAKELPARAM(LVNI_SELECTED, 0));
		if (-1 == index)
		{
			EnableWindow(GetDlgItem(_hDlg, IDC_CERTDELETE), FALSE);
		}
		else
		{
			EnableWindow(GetDlgItem(_hDlg, IDC_CERTDELETE), TRUE);
		}
		EnableWindow(GetDlgItem(_hDlg, IDC_TOKEN_LOGIN), HasSession() && (!Session()->IsValid() || !Session()->IsLoggedIn()));
	}
    intptr_t InitSettings()
	{
		int index;
		CWaitCursor wc;
		tscrypto::tsCryptoString selection;

		if (InitTokenInfoList())
		{
			InitTokenComboBox();
		}
		else
		{
			LOG(DebugError, "Unable to find any Tokens.");
			_initialized = true;
			return 0;
		}
		AddGroupText(AS_SEL_DOM_STR);
		EnableWindow(_GroupCtrl, FALSE);

		//SendMessage(_CryptoGroupCombo, CB_RESETCONTENT, 0, 0);
		//SendMessage(_CryptoGroupCombo, CB_ADDSTRING, 0, (LPARAM)AS_SEL_DOM_STR);
		//SendMessage(_CryptoGroupCombo, CB_ADDSTRING, 0, (LPARAM)AS_SEL_DOM_STR); // Add extra to ensure an ON_CBN_SELENDOK message is thrown
		//SendMessage(_CryptoGroupCombo, CB_SETCURSEL, 0, 0);
		EnableWindow(GetDlgItem(_hDlg, IDC_TOKEN_LOGIN), HasSession() && (!Session()->IsValid() || !Session()->IsLoggedIn()));

		UpdateDialogControls();

		// get the list of favorites and the "default" favorite
		InitFavorites();
		// TODO:  Implement me
		/*
		myFavs.GetDefaultFavorite(selection);
		*/

		// TODO:  Implement change detection for tokens
		//m_tokenChange = new TokenChangeDetector(_hDlg);
		//m_tokenChangeCookie = gMonitor->RegisterChangeConsumer(m_tokenChange);
		//gConsumerCookieList.add(m_tokenChangeCookie);

		// if we are in favorites creation mode, do some special stuff
		if (_CreateFavorites)
		{
			//SendMessage(_CryptoGroupCombo, CB_RESETCONTENT, 0, 0);
			//SendMessage(_CryptoGroupCombo, CB_ADDSTRING, 0, (LPARAM)"<No Token Selected>");
			//SendMessage(_CryptoGroupCombo, CB_SETCURSEL, 0, 0);
			UpdateDialogControls();
			_initialized = true;
			//SetTimer(_hDlg, 1, 500, NULL);
			return 1;
		}

		// TODO:  Implement me
		/*    // if we are supposed to remember favorites, load it up
		if (myRememberFavorite && selection.GetLength() &&
		(-1 != _FavoriteCombo.SelectString(-1, selection)))
		{
		OnChangeFavorite();
		UpdateDialogControls();
		initialized = TRUE;
		return 1;
		}
		*/

		// otherwise, get the default token for the app/system
		// and select that token as the default token

		std::shared_ptr<IKeyVEILSession> session;

		// TODO:  Reimplement this if we have application related tokens again
		//if (SUCCEEDED(gLoadedCkmFunctions->keyGenFunctions->RetrieveApplicationToken(myAppName.c_str(), &session)))
		//{
		//	int count = (int)SendMessage(_TokenCombo, CB_GETCOUNT, 0, 0);
		//	std::shared_ptr<ICKMTokenProvider> prov;
		//	DWORD provId = (DWORD)-1;
		//	DWORD slot = session->GetSlotID();

		//	if (SUCCEEDED(session->GetProvider(&prov)))
		//	{
		//		provId = prov->ProviderID();
		//	}

		//	for (index = 0; index < count; index++)
		//	{
		//		TokenInfo *info = (TokenInfo *)SendMessage(_TokenCombo, CB_GETITEMDATA, index, 0);

		//		if (info != NULL && info->slot == slot)
		//		{
		//			if (!!info->provider && info->provider->ProviderID() == provId)
		//			{
		//				break;
		//			}
		//		}
		//	}
		//	if (index >= count)
		//		index = 0;
		//}
		//else
		{
			index = 0;
		}
		//SendMessage(_TokenCombo, CB_SETCURSEL, index, 0);
		ChangeToken();
		_LastTokenSelection = index;

		UpdateDialogControls();

		_initialized = true;
		///PR 2965
		if (SendMessage(_FavoriteCombo, CB_GETCOUNT, 0, 0) != 0)
		{
			SetFocus(_FavoriteCombo);
		}
		else
		{
			SetFocus(_TokenCombo);
		}
		//SetTimer(_hDlg, 1, 500, NULL);
		return 1;
	}
	//intptr_t CryptoGroupPressLogin()
	//{
	//	asdfadsf
	//	populateCryptoGroupList();
	//	return TRUE;
	//}

	void EnableDisableOK()
	{
		int attributeCount = 0;
		BOOL bEnableOK = FALSE;
		BOOL bEnableFav = FALSE;

		attributeCount = (int)SendMessage(_GroupCtrl, LVM_GETITEMCOUNT, 0, 0);

		/* If there is more than one item in the list,...*/
		if (attributeCount > 0)
		{
			/* If there is one item and it is the "select cryptogroup" string, the box is really empty. */
			if (attributeCount == 1)
			{
				char name[512];
				LVITEMA item;

				memset(&item, 0, sizeof(item));
				item.mask = LVIF_TEXT;
				item.pszText = name;
				item.cchTextMax = sizeof(name) / sizeof(char);

				SendMessageA(_GroupCtrl, LVM_GETITEMTEXTA, 0, (LPARAM)&item);
				if (item.pszText != NULL && tsStrCmp(item.pszText, AS_SEL_DOM_STR) != 0)
				{
					bEnableOK = TRUE;
					bEnableFav = TRUE;
				}
			}
			else
			{
				bEnableOK = TRUE;
				bEnableFav = TRUE;
			}
		}

		// TODO:  Implement me when we support PKI
		//    if (mySelectedCertVector.size() > 0)
		//	{
		//        bEnableOK = TRUE;
		//		bEnableFav = TRUE;
		//	}
		attributeCount = (int)SendMessage(_RichCertList, LVM_GETITEMCOUNT, 0, 0);

		if (attributeCount > 0)
		{
			bEnableOK = TRUE;
			bEnableFav = TRUE;
		}

		if (SendMessage(GetDlgItem(_hDlg, IDC_USE_MY_CERT), BM_GETCHECK, 0, 0) == BST_CHECKED)
		{
			bEnableOK = TRUE;
		}

		EnableWindow(GetDlgItem(_hDlg, IDOK), bEnableOK);
		EnableWindow(GetDlgItem(_hDlg, IDC_CREATE_FAVORITE), bEnableFav);
		EnableWindow(GetDlgItem(_hDlg, IDC_DELETE_FAVORITE), _CreateFavorites && _CurFavIndex > 0);
	}

	bool InitTokenInfoList()
	{
		//std::shared_ptr<ICKMProviderList> provList;
		//std::shared_ptr<ICKMNonFiefdomKeyGenerator> builder;
		//std::shared_ptr<ICKMTokenProvider> prov;
		//std::shared_ptr<ICKMTokenList> tokenList;

		return true;
	}

	void InitTokenComboBox()
	{
		int index;
		size_t tokenCount;
		tscrypto::tsCryptoString name;
		std::shared_ptr<IToken> token;
		tscrypto::tsCryptoData tokenSerial;

		if (HasSession() && Session()->IsValid() && HasProfile() && GetProfile()->exists_SerialNumber())
		{
			tokenSerial = *GetProfile()->get_SerialNumber();
		}

		// Empty the  contents of the token combo
		SendMessage(_TokenCombo, CB_RESETCONTENT, 0, 0);

		if (!!_connector)
		{
			tokenCount = _connector->tokenCount();

			for (size_t tokenIter = 0; tokenIter < tokenCount; tokenIter++)
			{
				token.reset();
				token = _connector->token(tokenIter);
				if (!!token)
				{
					_tokenSerialNumbers.push_back(token->serialNumber());
					size_t serialidx = _tokenSerialNumbers.size() - 1;

					name = token->tokenName();

					if (name.size() == 0)
					{
						name.Format("%s%s", EMPTY_SLOT_PREFIX, EMPTY_SLOT_SUFFIX);
					}

					index = (int)SendMessage(_TokenCombo, CB_ADDSTRING, 0, (LPARAM)name.c_str());
					SendMessage(_TokenCombo, CB_SETITEMDATA, index, serialidx);
				}
			}
		}
		// If we have no tokens available in any slot, disable the control box.
		if (SendMessage(_TokenCombo, CB_GETCOUNT, 0, 0) == 0)
		{
			EnableWindow(_TokenCombo, FALSE);
		}
		if (tokenSerial.size() > 0)
		{
			int curToken = FindTokenOnComboBox(tokenSerial);
			if (curToken != -1)
				SendMessage(_TokenCombo, CB_SETCURSEL, curToken, 0);
		}
	}
	void OnTokenAdd(const tscrypto::tsCryptoData& serialNumber)
	{
		int curToken = FindTokenOnComboBox(serialNumber);
		int cursel = (int)SendMessage(_TokenCombo, CB_GETCURSEL, 0, 0);
		tscrypto::tsCryptoString name;

		if (!!_connector)
		{
			if (curToken == -1)
			{
				std::shared_ptr<IToken>         token;

				token = _connector->token(serialNumber);
				if (!!token)
				{
					_tokenSerialNumbers.push_back(token->serialNumber());
					size_t serialidx = _tokenSerialNumbers.size() - 1;

					name = token->tokenName();

					if (name.size() == 0)
					{
						name.Format("%s%s", EMPTY_SLOT_PREFIX, EMPTY_SLOT_SUFFIX);
					}

					curToken = (int)SendMessage(_TokenCombo, CB_ADDSTRING, 0, (LPARAM)name.c_str());
					SendMessage(_TokenCombo, CB_SETITEMDATA, curToken, serialidx);
				}
			}
			else
			{
				bool isSelected = (curToken == cursel);

				if (isSelected)
				{
					SendMessage(_TokenCombo, CB_SETCURSEL, (WPARAM)-1, 0);
				}

				int serialIndex = (int)SendMessage(_TokenCombo, CB_GETITEMDATA, curToken, 0);
				name.clear();

				if (serialIndex >= 0 && serialIndex < (int)_tokenSerialNumbers.size())
				{
					std::shared_ptr<IToken>         token;

					token = _connector->token(serialNumber);
					if (!!token)
					{
						name = token->tokenName();
					}
					if (name.size() == 0)
					{
						name.Format("%s%s", EMPTY_SLOT_PREFIX, EMPTY_SLOT_SUFFIX);
					}
					SendMessage(_TokenCombo, CB_DELETESTRING, curToken, 0);
					curToken = (int)SendMessage(_TokenCombo, CB_ADDSTRING, 0, (LPARAM)name.c_str());
					SendMessage(_TokenCombo, CB_SETITEMDATA, curToken, serialIndex);
					if (isSelected)
					{
						SendMessage(_TokenCombo, CB_SETCURSEL, curToken, 0);
						OnChangeTokenByControl();
					}
				}
			}
		}
	}

	void OnTokenRemove(const tscrypto::tsCryptoData& serialNumber)
	{
		int curToken = FindTokenOnComboBox(serialNumber);
		int cursel = (int)SendMessage(_TokenCombo, CB_GETCURSEL, 0, 0);
		char name[512];
		int nameLen = sizeof(name);

		if (curToken != -1)
		{
			bool isSelected = (curToken == cursel);

			if (isSelected)
			{
				SendMessage(_TokenCombo, CB_SETCURSEL, (WPARAM)-1, 0);
			}

			int serialIndex = (int)SendMessage(_TokenCombo, CB_GETITEMDATA, curToken, 0);
			name[0] = 0;
			nameLen = sizeof(name);
			tsSnPrintf(name, sizeof(name), "%s%s", EMPTY_SLOT_PREFIX, EMPTY_SLOT_SUFFIX);

			SendMessage(_TokenCombo, CB_DELETESTRING, curToken, 0);
			curToken = (int)SendMessage(_TokenCombo, CB_ADDSTRING, 0, (LPARAM)name);
			SendMessage(_TokenCombo, CB_SETITEMDATA, curToken, serialIndex);
			if (isSelected)
			{
				SendMessage(_TokenCombo, CB_SETCURSEL, curToken, 0);
				OnChangeTokenByControl();
			}
		}
	}

	//	void OnFavoriteAdd(const GUID& id)
	//	{
	//		int curFavorite = FindFavoriteOnComboBox(id);
	//		int cursel = (int)SendMessage(_FavoriteCombo, CB_GETCURSEL, 0, 0);
	//		tscrypto::tsCryptoString name;
	//
	//		if (curFavorite == -1)
	//		{
	//			std::shared_ptr<IFavorite>         favorite;
	//
	//			favorite = _connector->favorite(id);
	//			if (!!favorite)
	//			{
	//				int guidIndex = findGuidIndex(id, true);
	//
	//				name = favorite->favoriteName();
	//
	//				if (name.size() == 0)
	//				{
	//					name.Format("Unnamed Favorite");
	//				}
	//
	//				curFavorite = (int)SendMessage(_FavoriteCombo, CB_ADDSTRING, 0, (LPARAM)name.c_str());
	//				SendMessage(_FavoriteCombo, CB_SETITEMDATA, curFavorite, guidIndex);
	//			}
	//		}
	//		else
	//		{
	//			bool isSelected = (curFavorite == cursel);
	//
	//			if (isSelected)
	//			{
	//				SendMessage(_FavoriteCombo, CB_SETCURSEL, (WPARAM)-1, 0);
	//			}
	//
	//			int guidIndex = (int)SendMessage(_FavoriteCombo, CB_GETITEMDATA, curFavorite, 0);
	//			name.clear();
	//
	//			if (guidIndex >= 0 && guidIndex < _guidMap.size())
	//			{
	//				std::shared_ptr<IFavorite>         favorite;
	//
	//				favorite = _connector->favorite(id);
	//				if (!!favorite)
	//				{
	//					name = favorite->favoriteName();
	//				}
	//				if (name.size() == 0)
	//				{
	//					name.Format("%s%s", EMPTY_SLOT_PREFIX, EMPTY_SLOT_SUFFIX);
	//				}
	//				SendMessage(_FavoriteCombo, CB_DELETESTRING, curFavorite, 0);
	//				curFavorite = (int)SendMessage(_FavoriteCombo, CB_ADDSTRING, 0, (LPARAM)name.c_str());
	//				SendMessage(_FavoriteCombo, CB_SETITEMDATA, curFavorite, guidIndex);
	//				if (isSelected)
	//				{
	//					SendMessage(_FavoriteCombo, CB_SETCURSEL, curFavorite, 0);
	////					OnChangeTokenByControl();
	//				}
	//			}
	//		}
	//	}
	void OnTokenDataChange(const tscrypto::tsCryptoData& serialNumber)
	{
		// TODO:  Implement me
	}
	void OnTimer()
	{
		// TODO:  Implement me when we have token change detection
		//gMonitor->LookForChanges();
		//SetTimer(_hDlg, 1, 500, NULL);
	}
	void HidePKIControls()
	{
		// hide the controls we don't want to see in CKM mode
		//ShowWindow(GetDlgItem(_hDlg, IDC_RICHCERTLIST), SW_HIDE);
		ShowWindow(GetDlgItem(_hDlg, IDC_PEOPLE), SW_HIDE);
		//ShowWindow(GetDlgItem(_hDlg, IDC_STATIC1), SW_HIDE);
		//ShowWindow(GetDlgItem(_hDlg, IDC_STATIC2), SW_HIDE);
		//    ShowWindow(GetDlgItem(_hDlg, IDC_APPENDSIG), SW_HIDE);

		//RECT rect;
		//int height = 112;

		//GetWindowRect(GetDlgItem(_hDlg, IDC_CREATE_FAVORITE), &rect);
		//ScreenToClient(_hDlg, ((POINT*)&rect) + 0);
		//ScreenToClient(_hDlg, ((POINT*)&rect) + 1);
		//rect.top -= height;
		//rect.bottom -= height;
		//MoveWindow(GetDlgItem(_hDlg, IDC_CREATE_FAVORITE), rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top, TRUE);

		//GetWindowRect(GetDlgItem(_hDlg, IDHELP), &rect);
		//ScreenToClient(_hDlg, ((POINT*)&rect) + 0);
		//ScreenToClient(_hDlg, ((POINT*)&rect) + 1);
		//rect.top -= height;
		//rect.bottom -= height;
		//MoveWindow(GetDlgItem(_hDlg, IDHELP), rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top, TRUE);

		//GetWindowRect(GetDlgItem(_hDlg, IDOK), &rect);
		//ScreenToClient(_hDlg, ((POINT*)&rect) + 0);
		//ScreenToClient(_hDlg, ((POINT*)&rect) + 1);
		//rect.top -= height;
		//rect.bottom -= height;
		//MoveWindow(GetDlgItem(_hDlg, IDOK), rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top, TRUE);

		//GetWindowRect(GetDlgItem(_hDlg, IDCANCEL), &rect);
		//ScreenToClient(_hDlg, ((POINT*)&rect) + 0);
		//ScreenToClient(_hDlg, ((POINT*)&rect) + 1);
		//rect.top -= height;
		//rect.bottom -= height;
		//MoveWindow(GetDlgItem(_hDlg, IDCANCEL), rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top, TRUE);

		//GetWindowRect(_hDlg, &rect);
		//rect.bottom -= (height );
		//MoveWindow(_hDlg, rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top, TRUE);

		_PKIHidden = true;
	}
	BOOL CheckAccessGroup(std::shared_ptr<ICmsHeaderAttributeGroup> newAttrs)
	{
		int index;
		int matchCount = 0;
		tscrypto::tsCryptoData newList;
		tscrypto::tsCryptoData oldList;
		std::shared_ptr<ICmsHeaderAttributeGroup> attrs;
		std::shared_ptr<ICmsHeaderAccessGroup> andGroup;
		int attrListCount;

		BuildIntList(newAttrs, newList);

		std::shared_ptr<ICmsHeaderExtension> ext;
		std::shared_ptr<ICmsHeaderAccessGroupExtension> groupList;

		if (!_header || !_header->GetProtectedExtensionByOID(tscrypto::tsCryptoData(id_TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), ext) ||
			!(groupList = std::dynamic_pointer_cast<ICmsHeaderAccessGroupExtension>(ext)))
		{
			return FALSE;
		}

		attrListCount = (int)groupList->GetAccessGroupCount();
		for (index = 0; index < attrListCount; index++)
		{
			andGroup.reset();
			attrs.reset();

			if ((groupList->GetAccessGroup(index, andGroup)) && !!(attrs = std::dynamic_pointer_cast<ICmsHeaderAttributeGroup>(andGroup)))
			{
				BuildIntList(attrs, oldList);
				if (oldList.size() == newList.size() && memcmp(oldList.c_str(), newList.c_str(), oldList.size()) == 0)
				{
					matchCount++;
				}
			}
		}

		//
		// Since the access group is already added to the header, we expect to see one match.
		//
		if (matchCount != 1)
		{
			return FALSE;
		}
		//
		// Now clear the attrs in the new attr list and put the sorted attrs into the list.
		//
		while (newAttrs->GetAttributeCount() > 0)
			newAttrs->RemoveAttributeIndex(0);

		for (index = 0; index < (int)newList.size() / 4; index++)
		{
			newAttrs->AddAttributeIndex(((DWORD*)newList.c_str())[index]);
		}
		return TRUE;
	}
	void BuildIntList(std::shared_ptr<ICmsHeaderAttributeGroup> attrGroup, tscrypto::tsCryptoData &list)
	{
		int attributeCount;
		DWORD *p;
		int insertedCount = 0;
		DWORD id;
		int i, j;

		attributeCount = (int)attrGroup->GetAttributeCount();
		list.erase();
		list.resize(attributeCount * 4);
		p = (DWORD*)list.rawData();

		for (i = 0; i < attributeCount; i++)
		{
			id = attrGroup->GetAttributeIndex(i);
			//
			// Now insert sort the value
			//
			for (j = 0; j < insertedCount; j++)
			{
				if (id < p[j])
				{
					memmove(&p[j + 1], &p[j], (insertedCount - j) * 4);
					p[j] = id;
					insertedCount++;
					break;
				}
			}
			if (j == insertedCount)
			{
				p[j] = id;
				insertedCount++;
			}
		}
	}
	bool FindSelectedAccessGroup(std::shared_ptr<ICmsHeaderAccessGroup>& accessGroup, std::shared_ptr<ICmsHeaderAttributeGroup>& attrs)
	{
		tscrypto::tsCryptoString line;
		std::shared_ptr<ICmsHeaderAccessGroup>   andGroup;
		std::shared_ptr<ICmsHeaderAttributeGroup>  attrGroup;
		int accessGroupCount;
		int sel;
		int index;
		char name[512];
		LVITEMA lvitem;

		if (!_header)
			return false;

		std::shared_ptr<ICmsHeaderExtension> ext;
		std::shared_ptr<ICmsHeaderAccessGroupExtension> extGroup;
		if (!_header->GetProtectedExtensionByOID(tscrypto::tsCryptoData(id_TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), ext) ||
			!(extGroup = std::dynamic_pointer_cast<ICmsHeaderAccessGroupExtension>(ext)))
		{
			return false;
		}
		ext.reset();

		attrs.reset();
		accessGroup.reset();

		sel = (int)SendMessage(_GroupCtrl, LVM_GETNEXTITEM, (WPARAM)-1, MAKELPARAM(LVNI_SELECTED, 0));

		memset(&lvitem, 0, sizeof(lvitem));
		lvitem.mask = LVIF_TEXT;
		lvitem.pszText = name;
		lvitem.cchTextMax = sizeof(name) / sizeof(char);
		lvitem.iItem = sel;
		SendMessageA(_GroupCtrl, LVM_GETITEMA, 0, (LPARAM)&lvitem);

		accessGroupCount = (int)extGroup->GetAccessGroupCount();
		for (index = 0; index < accessGroupCount; index++)
		{
			andGroup.reset();
			attrGroup.reset();

			if ((extGroup->GetAccessGroup(index, andGroup)) &&
				andGroup->GetAndGroupType() == ag_Attrs &&
				!!(attrGroup = std::dynamic_pointer_cast<ICmsHeaderAttributeGroup>(andGroup)))
			{
				line = BuildAttrsLine(attrGroup);
				if (tsStrCmp(line.c_str(), name) == 0)
				{
					attrs = attrGroup;
					accessGroup = andGroup;
					return true;
				}
			}
		}

		return false;
	}
	int findGuidIndex(const GUID& id, bool insert = false)
	{
		for (size_t i = 0; i < _guidMap.size(); i++)
		{
			if (_guidMap[i] == id)
			{
				return (int)i;
			}
		}
		if (!insert)
			return -1;
		_guidMap.push_back(id);
		return (int)_guidMap.size() - 1;
	}
	void InitFavorites()
	{
		std::shared_ptr<IFavorite> fav;
		int index = -1;
		DWORD favIndex;
		size_t count = 0;
		tscrypto::tsCryptoString name;

		if (!!_connector)
			count = _connector->favoriteCount();

		/* If no favorites found, disable the favorite list. */
		if (count == 0)
		{
			EnableWindow(_FavoriteCombo, FALSE);
			return;
		}
		else
		{
			EnableWindow(_FavoriteCombo, TRUE);
		}

		SendMessage(_FavoriteCombo, CB_RESETCONTENT, 0, 0);
		if (!!_connector)
		{
			for (favIndex = 0; favIndex < count; favIndex++)
			{
				fav.reset();
				if (!!(fav = _connector->favorite(favIndex)))
				{
					name = fav->favoriteName();
					if (SendMessage(_FavoriteCombo, CB_FINDSTRING, 0, (LPARAM)name.c_str()) == -1)
					{
						index = (int)SendMessage(_FavoriteCombo, CB_ADDSTRING, 0, (LPARAM)name.c_str());
						SendMessage(_FavoriteCombo, CB_SETITEMDATA, index, findGuidIndex(fav->favoriteId(), true));
					}
				}
			}
		}
		SendMessage(_FavoriteCombo, CB_INSERTSTRING, 0, (LPARAM)SAVE_FAVORITE_LINE);
		SendMessage(_FavoriteCombo, CB_SETCURSEL, _CurFavIndex, 0);

		/* If no tokens that matched favorites were found, disable the favorite list. */
		//if ( index == -1 )
		//{
		//    SendMessage(myFavoriteCombo, CB_ADDSTRING, 0, (LPARAM)("<Favorites Not Available>"));
		//    EnableWindow(myFavoriteCombo, FALSE);
		//}
	}
	int  FindTokenOnComboBox(const tscrypto::tsCryptoData& serialNumber)
	{
		int count;
		int index;
		int serialIndex = -1;
		int ser;

		for (size_t i = 0; i < _tokenSerialNumbers.size(); i++)
		{
			if (_tokenSerialNumbers[i] == serialNumber)
			{
				serialIndex = (int)i;
				break;
			}
		}
		if (serialIndex == -1)
			return -1;

		count = (int)SendMessage(_TokenCombo, CB_GETCOUNT, 0, 0);
		for (index = 0; index < count; index++)
		{
			ser = (int)SendMessage(_TokenCombo, CB_GETITEMDATA, index, 0);
			if (ser != -1)
			{
				if (ser == serialIndex)
					return index;
			}
		}
		return -1;
	}

};

tsmod::IObject* CreateAudienceSelector()
{
	return dynamic_cast<tsmod::IObject*>(new AudienceSelector(false));
}
tsmod::IObject* CreateFavoriteEditer()
{
	return dynamic_cast<tsmod::IObject*>(new AudienceSelector(true));
}