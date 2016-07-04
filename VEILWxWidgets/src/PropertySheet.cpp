//	Copyright (c) 2016, TecSec, Inc.
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
//#include "help/VEILSystemHelp.h"

//#define DATA_ENCRYPTION_STANDARD	"The Data Encryption Standard Algorithm, frequently referred to as DES, is widely used within government and financial organizations.  Its use of 56-bit keys provides adequate protection in most situations, although the level of protection provided by DES is not as strong as that available with other algorithms."
//#define TRIPLE_DES					"In general terms, the Triple-DES algorithm improves on the standard DES protection by encoding information three times with as many as three different keys.  Its protection of information is strong enough to meet the most demanding requirements.  Triple-DES achieves this level of protection, however, at the cost of performance.  Especially when implemented in software,  Triple-DES is approximately three times slower than standard DES, and 25-40 times slower than TecSec's P-Squared algorithm (depending on file size and mode of Triple-DES used).Although all of the algorithms described here are available to all members, Triple-DES (two key) is the default algorithm - it encodes information three times with two different keys"
//#define PSQUARED					"P-Squared is TecSec's proprietary high performance cryptographic algorithm.  Based on principles developed and studied by the U.S. government for more than 50 years, P-Squared provides cryptographic protection that meets even the most demanding requirements.  Furthermore, P-Squared has been optimized for high performance - encrypting and decrypting files 7-15 times faster than standard DES and 25-40 times faster than Triple-DES (depending on the size of the file and the modes of DES being used).P-Squared is most suited to situations requiring the highest performance while not compromising cryptographic information.  It works well through a wide range of processor speeds and available memory."


struct PageDescriptor
{
	PageDescriptor() : focusSet(false) {}

	tscrypto::tsCryptoString url;
	std::shared_ptr<IVEILPropertyPage> _page;
	bool focusSet;
};

//class VEILFileSettingsHandler
//{
//public:
//	static std::function<int64_t(XP_WINDOW, uint32_t, uint64_t, uint64_t)> Create(std::shared_ptr<BasicVEILPreferences> prefs)
//	{
//		std::shared_ptr<VEILFileSettingsHandler> _me = std::shared_ptr<VEILFileSettingsHandler>(new VEILFileSettingsHandler());
//		_me->_prefs = prefs;
//		return [_me](XP_WINDOW wnd, uint32_t msg, uint64_t wParam, uint64_t lParam)->int64_t{ return _me->VEILFileSettingsHandler::dlgProc((HWND)wnd, msg, (WPARAM)wParam, (LPARAM)lParam); };
//	}
//	~VEILFileSettingsHandler(){}
//
//protected:
//
//	virtual BOOL OnApply()
//	{
//	}
//
//	BOOL ValidateTimeOutEdit()
//	{
//		char buff[50] = ("");
//		unsigned int value;
//		HWND pEdit;
//		int numChars = GetDlgItemTextA(m_hWnd, IDC_TIME_OUT_EDIT, buff, sizeof(buff));
//
//		if (numChars == 0)
//		{
//			MessageBoxA(m_hWnd, ("Please enter a number between 0 and 999."),
//				("VEIL Settings Timeout Preferences"), MB_OK | MB_ICONWARNING);
//
//			pEdit = GetDlgItem(m_hWnd, IDC_TIME_OUT_EDIT);
//			SetFocus(pEdit);
//			SendMessage(pEdit, EM_SETSEL, 0, -1);
//			return FALSE;
//		}
//
//		value = TsStrToInt(buff);
//		if (value > 999)
//		{
//			MessageBoxA(m_hWnd, ("Please enter a number between 0 and 999."),
//				("VEIL Settings Timeout Preferences"), MB_OK | MB_ICONWARNING);
//
//			pEdit = GetDlgItem(m_hWnd, IDC_TIME_OUT_EDIT);
//			SetFocus(pEdit);
//			SendMessage(pEdit, EM_SETSEL, 0, -1);
//			return FALSE;
//		}
//
//		return TRUE;
//	}
//
//
//	// TODO finish implmentation
//	//BOOL ValidatePositionEdit()
//	//{
//	//	char buff[50] = ("");
//	//	unsigned int value;
//	//	HWND pEdit;
//	//	// LEFT
//	//	int numChars = GetDlgItemTextA(m_hWnd, IDC_POSLEFT, buff, sizeof(buff));
//
//	//	if (numChars == 0)
//	//	{
//	//		MessageBoxA(m_hWnd, ("Please enter a number between 0 and 1200."),
//	//			("VEIL Settings Left Position Preferences"), MB_OK | MB_ICONWARNING);
//
//	//		pEdit = GetDlgItem(m_hWnd, IDC_POSLEFT);
//	//		SetFocus(pEdit);
//	//		SendMessage(pEdit, EM_SETSEL, 0, -1);
//	//		return FALSE;
//	//	}
//
//	//	value = TsStrToInt(buff);
//
//	//	if (value > 1200)
//	//	{
//	//		MessageBoxA(m_hWnd, ("Please enter a number from 0 and 1200."),
//	//			("VEIL Settings Left Position Preferences"), MB_OK | MB_ICONWARNING);
//
//	//		pEdit = GetDlgItem(m_hWnd, IDC_POSLEFT);
//	//		SetFocus(pEdit);
//	//		SendMessage(pEdit, EM_SETSEL, 0, -1);
//	//		return FALSE;
//	//	}
//	//	// TOP
//	//	numChars = GetDlgItemTextA(m_hWnd, IDC_POSTOP, buff, sizeof(buff));
//
//	//	if (numChars == 0)
//	//	{
//	//		MessageBoxA(m_hWnd, ("Please enter a number between 0 and 780."),
//	//			("VEIL Settings Top Position Preferences"), MB_OK | MB_ICONWARNING);
//
//	//		pEdit = GetDlgItem(m_hWnd, IDC_POSTOP);
//	//		SetFocus(pEdit);
//	//		SendMessage(pEdit, EM_SETSEL, 0, -1);
//	//		return FALSE;
//	//	}
//
//	//	value = TsStrToInt(buff);
//
//	//	if (value > 780)
//	//	{
//	//		MessageBoxA(m_hWnd, ("Please enter a number from 0 and 780."),
//	//			("VEIL Settings Top Position Preferences"), MB_OK | MB_ICONWARNING);
//
//	//		pEdit = GetDlgItem(m_hWnd, IDC_POSTOP);
//	//		SetFocus(pEdit);
//	//		SendMessage(pEdit, EM_SETSEL, 0, -1);
//	//		return FALSE;
//	//	}
//
//	//	return TRUE;
//	//}
//
//	void OnCloseAftOpnChk()
//	{
//		SetModified();
//	}
//
//	void OnCompEncChk()
//	{
//		SetModified();
//	}
//
//	void OnDelAftDecVerChk()
//	{
//		if (SendDlgItemMessage(m_hWnd, IDC_DEL_AFT_DECVER_CHK, BM_GETCHECK, 0, 0) == BST_CHECKED)
//		{
//			if (wxID_YES == MessageBoxA
//				(m_hWnd, "Selecting this option will securely delete your original "
//				"file following Decryption.  "
//				//                             "file following Decryption or Verification operations.  "
//				"You will not be able to recover the original.  "
//				"Do you wish to continue?",
//				"CKM Desktop Preferences", MB_YESNO | MB_ICONWARNING))
//			{
//				SetModified();
//			}
//			else
//			{
//				SendDlgItemMessage(m_hWnd, IDC_DEL_AFT_DECVER_CHK, BM_SETCHECK, BST_UNCHECKED, 0);
//			}
//		}
//		else
//		{
//			SetModified();
//		}
//	}
//
//	void OnDelAftEncChk()
//	{
//		if (SendDlgItemMessage(m_hWnd, IDC_DEL_AFT_ENC_CHK, BM_GETCHECK, 0, 0) == BST_CHECKED)
//		{
//			if (wxID_YES == MessageBoxA
//				(m_hWnd, "Selecting this option will securely delete your original "
//				"file following Encryption operations.  "
//				"You will not be able to recover the original.  "
//				"Do you wish to continue?",
//				"CKM Desktop Preferences", MB_YESNO | MB_ICONWARNING))
//			{
//				SetModified();
//			}
//			else
//			{
//				SendDlgItemMessage(m_hWnd, IDC_DEL_AFT_ENC_CHK, BM_SETCHECK, BST_UNCHECKED, 0);
//			}
//		}
//		else
//		{
//			SetModified();
//		}
//	}
//
//	void OnDelAftSigChk()
//	{
//		//if( SendDlgItemMessage(m_hWnd, IDC_DEL_AFT_SIG_CHK, BM_GETCHECK, 0, 0) == BST_CHECKED )
//		//{
//		//    if( wxID_YES == MessageBoxA
//		//                    (m_hWnd, "Selecting this option will securely delete your original "
//		//                     "file following Signing operations.  "
//		//                     "You will not be able to recover the original.  "
//		//                     "Do you wish to continue?",
//		//                     "CKM Desktop Preferences", MB_YESNO | MB_ICONWARNING) )
//		//    {
//		//        SetModified();
//		//    }
//		//    else
//		//    {
//		//         //Uncheck the box
//		//        SendDlgItemMessageA(m_hWnd, IDC_DEL_AFT_SIG_CHK, BM_SETCHECK, BST_UNCHECKED, 0);
//		//    }
//		//}
//		//else
//		//{
//		//    SetModified();
//		//}
//	}
//
//	void OnChangeTimeOutEdit()
//	{
//		SetModified();
//	}
//
//	void OnOvrExistChk()
//	{
//		SetModified();
//	}
//	void OnChangeSecureDelete()
//	{
//		SetModified();
//	}
//
//	void OnAlwaysOnTopChk()
//	{
//		SetModified();
//	}
//
//	void OnPosLeftEdit()
//	{
//		SetModified();
//	}
//
//	void OnPosTopEdit()
//	{
//		SetModified();
//	}
//
//	void OnSelchangeCompTypeCombo()
//	{
//		int index;
//
//		index = (int)SendMessage(m_cbxCompType, CB_GETCURSEL, 0, 0);
//
//		if (index == CB_ERR)
//			return;
//
//		//        SendMessage(m_cbxCompType, CB_SETCURSEL, index, 0);
//		SetModified();
//
//		m_CompType = index;
//		UpdateData(FALSE);
//	}
//
//	INT_PTR CALLBACK dlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
//	{
//		BOOL handled = FALSE;
//
//		switch (msg)
//		{
//		case WM_INITDIALOG:
//			m_hWnd = hWnd;
//			OnInitDialog();
//			break;
//		case WM_COMMAND:
//			//if ( wParam == MAKEWPARAM(IDC_ALLOW_CERT_ENC_CHK, BN_CLICKED) )
//			//{
//			//    This->OnAllowCertEncChk();
//			//    return TRUE;
//			//} else 
//			if (wParam == MAKEWPARAM(IDC_CLOSE_AFT_OPN_CHK, BN_CLICKED))
//			{
//				OnCloseAftOpnChk();
//				return TRUE;
//			}
//			else if (wParam == MAKEWPARAM(IDC_DEL_AFT_DECVER_CHK, BN_CLICKED))
//			{
//				OnDelAftDecVerChk();
//				return TRUE;
//			}
//			else if (wParam == MAKEWPARAM(IDC_DEL_AFT_ENC_CHK, BN_CLICKED))
//			{
//				OnDelAftEncChk();
//				return TRUE;
//			}
//			//else if (wParam == MAKEWPARAM(IDC_DEL_AFT_SIG_CHK, BN_CLICKED))
//			//{
//			//	OnDelAftSigChk();
//			//	return TRUE;
//			//}
//			else if (wParam == MAKEWPARAM(IDC_OVR_EXIST_CHK, BN_CLICKED))
//			{
//				OnOvrExistChk();
//				return TRUE;
//			}
//			else if (wParam == MAKEWPARAM(IDC_TIME_OUT_EDIT, EN_CHANGE))
//			{
//				OnChangeTimeOutEdit();
//				return TRUE;
//			}
//			else if (wParam == MAKEWPARAM(IDC_SECURE_DELETE, EN_CHANGE))
//			{
//				OnChangeSecureDelete();
//				return TRUE;
//			}
//			//else if ( wParam == MAKEWPARAM(IDC_CKMFILE_CHECK, BN_CLICKED) )
//			//{
//			//    This->OnCkmdesktopCheck();
//			//    return TRUE;
//			//}
//			else if (wParam == MAKEWPARAM(IDC_ALWAYSONTOP, BN_CLICKED))
//			{
//				OnAlwaysOnTopChk();
//				return TRUE;
//			}
//			//else if (wParam == MAKEWPARAM(IDC_POSLEFT, EN_CHANGE))
//			//{
//			//	OnPosLeftEdit();
//			//	return TRUE;
//			//}
//			//else if (wParam == MAKEWPARAM(IDC_POSTOP, EN_CHANGE))
//			//{
//			//	OnPosTopEdit();
//			//	return TRUE;
//			//}
//			else if (wParam == MAKEWPARAM(IDC_COMPTYPE_COMBO, CBN_SELCHANGE))
//			{
//				OnSelchangeCompTypeCombo();
//				return TRUE;
//			}
//			break;
//		case WM_NOTIFY:
//			switch (((NMHDR*)lParam)->code)
//			{
//			case PSN_HELP:
//				{
//				tscrypto::tsCryptoString path;
//					
//					//if ( !xp_PathSearch("CKMDesktop.chm", path) )
//					//{
//					//	MessageBoxA(hWnd, "We were unable to locate the help file for the VEIL system.", "Error", MB_OK);
//					//}
//					//else
//					//{
//					//	//        TS_HtmlHelp(m_hWnd, path, HH_DISPLAY_TOC, 0);
//					//	//		TS_HtmlHelp(m_hWnd, path, HH_DISPLAY_TOC, IDH_MNGT_CKMfile);
//					//	TS_HtmlHelp((XP_WINDOW)hWnd, path, HH_HELP_CONTEXT, IDH_MNGT_CKMfile);
//					//}
//
//					MessageBoxA(hWnd, "Help is not available at this time.", "Status", MB_OK);
//				}
//				break;
//			case PSN_APPLY:
//				if (!OnApply())
//				{
//					SetWindowLongPtr(hWnd, DWLP_MSGRESULT, PSNRET_INVALID);
//				}
//				else
//				{
//					SetWindowLongPtr(hWnd, DWLP_MSGRESULT, PSNRET_NOERROR);
//				}
//				break;
//			case PSN_KILLACTIVE:
//				// Validate controls here
//				if (!ValidateTimeOutEdit() /*|| !ValidatePositionEdit()*/)
//					SetWindowLongPtr(hWnd, DWLP_MSGRESULT, TRUE);
//				else
//					SetWindowLongPtr(hWnd, DWLP_MSGRESULT, FALSE);
//				break;
//			case PSN_QUERYCANCEL:
//				// Return TRUE to not allow CANCEL
//				SetWindowLongPtr(hWnd, DWLP_MSGRESULT, FALSE);
//				break;
//			case PSN_QUERYINITIALFOCUS:
//				SetWindowLongPtr(hWnd, DWLP_MSGRESULT, 0);
//				break;
//			case PSN_RESET:
//				break;
//			case PSN_SETACTIVE:
//				// Return 0 to accept the activation or -1 otherwise
//				SetWindowLongPtr(hWnd, DWLP_MSGRESULT, 0);
//				break;
//			case PSN_TRANSLATEACCELERATOR:
//				// Requesting normal handling
//				SetWindowLongPtr(hWnd, DWLP_MSGRESULT, PSNRET_NOERROR);
//				break;
//			}
//			break;
//		}
//		return handled;
//	}
//
//};

class VEILPropertySheet : public IVEILPropertySheet, public tsmod::IObject, public wxPropertySheetDialog
{
public:
	VEILPropertySheet() : _parent(nullptr), notebook(nullptr), btnApply(nullptr)
	{
		_prefs = BasicVEILPreferences::Create();
		if (!!_prefs)
		{
			_prefs->loadValues();
			_prefs->StartMonitor();
		}
	}
	virtual ~VEILPropertySheet()
	{
	}

	// wxPropertySheetDialog
	virtual bool Destroy() override
	{
		_parent = XP_WINDOW_INVALID;
		for (PageDescriptor &pg : pages)
		{
			if (!!pg._page)
			{
				pg._page->Reset();
				pg._page->Destroy();
			}
			pg._page.reset();
			pg.focusSet = false;
		}
		notebook = nullptr;
		btnApply = nullptr;
		Me.reset();
		return true;
	}

	// Inherited via IVEILPropertySheet
	virtual void PageModified(bool setTo) override
	{
		if (btnApply != nullptr)
			btnApply->Enable(setTo);
	}
	virtual int DisplayModal(XP_WINDOW parent, PropertySheetType type) override
	{
		Destroy();
		_parent = parent;

		Me = std::dynamic_pointer_cast<VEILPropertySheet>(_me.lock());

		SetExtraStyle(wxDIALOG_EX_CONTEXTHELP | wxWS_EX_VALIDATE_RECURSIVELY);

		int tabImage1 = -1;
		int tabImage2 = -1;

		bool useToolBook = (type == ToolBook || type == ButtonToolBook);
		int resizeBorder = wxRESIZE_BORDER;

		if (useToolBook)
		{
			resizeBorder = 0;
			tabImage1 = 0;
			tabImage2 = 1;

			int sheetStyle = wxPROPSHEET_SHRINKTOFIT;
			if (type == ButtonToolBook)
				sheetStyle |= wxPROPSHEET_BUTTONTOOLBOOK;
			else
				sheetStyle |= wxPROPSHEET_TOOLBOOK;

			SetSheetStyle(sheetStyle);
			SetSheetInnerBorder(0);
			SetSheetOuterBorder(0);

			//// create a dummy image list with a few icons
			//const wxSize imageSize(32, 32);

			//m_imageList = new wxImageList(imageSize.GetWidth(), imageSize.GetHeight());
			//m_imageList->
			//	Add(wxArtProvider::GetIcon(wxART_INFORMATION, wxART_OTHER, imageSize));
			//m_imageList->
			//	Add(wxArtProvider::GetIcon(wxART_QUESTION, wxART_OTHER, imageSize));
			//m_imageList->
			//	Add(wxArtProvider::GetIcon(wxART_WARNING, wxART_OTHER, imageSize));
			//m_imageList->
			//	Add(wxArtProvider::GetIcon(wxART_ERROR, wxART_OTHER, imageSize));
		}
		//else
		//	m_imageList = NULL;

		Create((wxWindow*)_parent, wxID_ANY, _("Preferences"), wxDefaultPosition, wxDefaultSize,
			wxDEFAULT_DIALOG_STYLE | (int)wxPlatform::IfNot(wxOS_WINDOWS_CE, resizeBorder)
			);

		// If using a toolbook, also follow Mac style and don't create buttons
		if (!useToolBook)
			CreateButtons(wxOK | wxCANCEL | wxAPPLY |
				(int)wxPlatform::IfNot(wxOS_WINDOWS_CE, wxHELP)
				);

		notebook = GetBookCtrl();
		//notebook->SetImageList(m_imageList);

		// Instantiate the objects
		for (PageDescriptor& pg : pages)
		{
			if (!pg._page)
				pg._page = ::TopServiceLocator()->try_get_instance<IVEILPropertyPage>(pg.url.c_str());
		}

		// Now remove any from the list that we could not build
		pages.erase(std::remove_if(pages.begin(), pages.end(), [](PageDescriptor& pg) { return !pg._page; }), pages.end());

		bool selectMe = true;
		for (PageDescriptor& pg : pages)
		{
			pg._page->SetParent(Me);
			notebook->AddPage((wxPanel*)(wxWindow*)pg._page->CreatePage((XP_WINDOW)notebook), pg._page->Title().c_str(), selectMe);
			selectMe = false;
		}



		LayoutDialog();

		Connect(wxID_OK, wxEVT_BUTTON, wxCommandEventHandler(VEILPropertySheet::OnOkClicked), nullptr, (wxPropertySheetDialog*)this);
		Connect(wxID_CANCEL, wxEVT_BUTTON, wxCommandEventHandler(VEILPropertySheet::OnCancelClicked), nullptr, (wxPropertySheetDialog*)this);
		Connect(wxID_APPLY, wxEVT_BUTTON, wxCommandEventHandler(VEILPropertySheet::OnApplyClicked), nullptr, (wxPropertySheetDialog*)this);
		Connect(wxID_HELP, wxEVT_BUTTON, wxCommandEventHandler(VEILPropertySheet::OnHelpClicked), nullptr, (wxPropertySheetDialog*)this);
		notebook->Connect(wxEVT_NOTEBOOK_PAGE_CHANGING, wxNotebookEventHandler(VEILPropertySheet::OnPageChanging), nullptr, (wxPropertySheetDialog*)this);
		notebook->Connect(wxEVT_NOTEBOOK_PAGE_CHANGED, wxNotebookEventHandler(VEILPropertySheet::OnPageChanged), nullptr, (wxPropertySheetDialog*)this);

		btnApply = FindWindow(wxID_APPLY);

		if (btnApply != nullptr)
			btnApply->Enable(false);

		int retVal = ShowModal();
		// Make sure you call Destroy
		Destroy();
		return retVal;
	}
	virtual void AddStandardPage(StandardPropPage pageType) override
	{
		PageDescriptor page;

		switch (pageType)
		{
		case IVEILPropertySheet::VEILFileSettings:
			page.url = "/WxWin/VEILFileSettingsPage";
			pages.push_back(page);
			break;
		case IVEILPropertySheet::GeneralSettings:
			page.url = "/WxWin/GeneralSettingsPage";
			pages.push_back(page);
			break;
		}
	}
	virtual void AddCustomPage(const tscrypto::tsCryptoString& link) override
	{
		PageDescriptor page;

		if (pages.size() >= 10)
			return;

		page.url = link;
		pages.push_back(page);
	}
	virtual std::shared_ptr<BasicVEILPreferences> BasicPreferences() override
	{
		return _prefs;
	}
protected:
	void OnOkClicked(wxCommandEvent& evt)
	{
		int index = notebook->GetSelection();

		evt.StopPropagation();
		if (index >= 0 && index < pages.size())
		{
			if (pages[index]._page->Apply() != IVEILPropertyPage::NoError)
				return;
		}
		EndDialog(wxID_OK);
	}
	void OnCancelClicked(wxCommandEvent& evt)
	{
		int index = notebook->GetSelection();

		evt.StopPropagation();
		if (index >= 0 && index < pages.size())
		{
			if (pages[index]._page->QueryCancel())
			{
				return;
			}
		}
		EndDialog(wxID_CANCEL);
	}
	void OnApplyClicked(wxCommandEvent& evt)
	{
		int index = notebook->GetSelection();

		evt.StopPropagation();
		if (index >= 0 && index < pages.size())
		{
			pages[index]._page->Apply();
		}
	}
	void OnHelpClicked(wxCommandEvent& evt)
	{
		int index = notebook->GetSelection();

		evt.StopPropagation();
		if (index >= 0 && index < pages.size())
		{
			pages[index]._page->OnHelp();
		}
	}
	void OnPageChanging(wxNotebookEvent& evt)
	{
		int index = evt.GetOldSelection();

		evt.StopPropagation();
		if (index >= 0 && index < pages.size())
		{
			if (pages[index]._page->KillActive())
			{
				evt.Veto();
				return;
			}
			if (pages[index]._page->Apply() != IVEILPropertyPage::NoError)
			{
				evt.Veto();
				return;
			}
		}

		index = evt.GetSelection();
		if (index >= 0 && index < pages.size())
		{
			if (pages[index]._page->SetActive())
			{
				evt.Veto();
				return;
			}
		}
	}
	void OnPageChanged(wxNotebookEvent& evt)
	{
		int index = evt.GetSelection();

		evt.Skip();
		if (index >= 0 && index < pages.size())
		{
			if (!pages[index].focusSet)
			{
				pages[index]._page->QueryInitialFocus();
				pages[index].focusSet = true;
			}
		}
	}
protected:
	XP_WINDOW  _parent;
	std::shared_ptr<VEILPropertySheet> Me;
	std::vector<PageDescriptor> pages;
	std::shared_ptr<BasicVEILPreferences> _prefs;
	wxBookCtrlBase* notebook;
	wxWindow* btnApply;
};

tsmod::IObject* CreateVEILPropertySheet()
{
	return dynamic_cast<tsmod::IObject*>(new VEILPropertySheet());
}


