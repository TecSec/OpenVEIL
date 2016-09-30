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

#define WM_POSTINIT            (WM_USER + 1001)
#define WM_CRYPTOGROUPLOGIN    (WM_USER + 1002)

#define AS_SEL_DOM_STR ("<Select a Crypto Group...>")
#define SAVE_FAVORITE_LINE ("<Save a new favorite>")

#define EMPTY_SLOT_PREFIX "<Slot "
#define EMPTY_SLOT_SUFFIX " Empty>"

////@begin control identifiers
#define ID_AUDIENCESELECTOR 10000
#define ID_FAVORITELIST 10001
#define ID_TOKENLIST 10002
#define ID_CGLIST 10003
#define ID_LISTBOX 10004
#define ID_ADD 10005
#define ID_EDIT 10006
#define ID_DELETE 10007
#define ID_CREATE_FAVORITE 10008
#define ID_DELETE_FAVORITE 10009
#define SYMBOL_AUDIENCESELECTOR_STYLE wxCAPTION|wxSYSTEM_MENU|wxCLOSE_BOX|wxTAB_TRAVERSAL
#define SYMBOL_AUDIENCESELECTOR_TITLE _("Audience Selector")
#define SYMBOL_AUDIENCESELECTOR_IDNAME ID_AUDIENCESELECTOR
#define SYMBOL_AUDIENCESELECTOR_SIZE wxSize(400, 350)
#define SYMBOL_AUDIENCESELECTOR_POSITION wxDefaultPosition
////@end control identifiers

class AudienceSelector : public IAudienceSelector, public tsmod::IObject, public wxDialog
{
	DECLARE_EVENT_TABLE()

public:
	AudienceSelector(bool createFavorites) : _CreateFavorites(createFavorites), _CurFavIndex(0), _LastTokenSelection(0), _initialized(false), _cookie(0), _ActiveCryptoGroup(nullptr)
	{
		Init();
	}
	virtual ~AudienceSelector()
	{
	}
	virtual void OnConstructionFinished() override
	{
		if (!::TopServiceLocator()->CanCreate("/CmsHeader"))
		{
			InitializeCmsHeader();
		}
		_header = ::TopServiceLocator()->get_instance<ICmsHeader>("/CmsHeader");
	}

	// wxDialog
	virtual bool Destroy() override
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
		_CreateFavorites = false;
		_AppName.clear();
		_CurFavIndex = 0;
		_LastTokenSelection = 0;
		_initialized = false;
		Me.reset();
		return true;
	}
	// IVEILWxUIBase
	virtual int  DisplayModal() override
	{
		if (_parent == XP_WINDOW_INVALID)
			_parent = (XP_WINDOW)wxTheApp->GetTopWindow();

		_header->Clear();

		// Construct the dialog here
		Create((wxWindow*)_parent);

		OnInitDialog();

		int retVal = ShowModal();

		// Make sure you call Destroy
		Destroy();
		return retVal;
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
	virtual bool Start(std::shared_ptr<IKeyVEILConnector> connector, XP_WINDOW parent, const tscrypto::tsCryptoString& appName) override
	{
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
						//OnTokenDataChange(eventData.AsString("serial").HexToData());
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

protected:
	XP_WINDOW                               _parent;
	std::shared_ptr<AudienceSelector> Me; // Keep me alive until Destroy is called
	std::shared_ptr<IKeyVEILSession>	    _session;
	std::shared_ptr<IKeyVEILConnector>	    _connector;
	std::shared_ptr<ICmsHeader>             _header;
	bool                                    _CreateFavorites;
	tscrypto::tsCryptoString							        _AppName;
	int									    _CurFavIndex;
	Asn1::CTS::_POD_CryptoGroup*					_ActiveCryptoGroup;
	int										_LastTokenSelection;
	std::shared_ptr<IFavorite>				_favorite;
	bool                                    _initialized;
	std::vector<tscrypto::tsCryptoData>                     _tokenSerialNumbers;
	std::vector<GUID>						_guidMap;
	size_t                                  _cookie;
	std::shared_ptr<Asn1::CTS::_POD_Profile>		_profile;

	/// Creation
	bool Create(wxWindow* parent, wxWindowID id = SYMBOL_AUDIENCESELECTOR_IDNAME, const wxString& caption = SYMBOL_AUDIENCESELECTOR_TITLE, const wxPoint& pos = SYMBOL_AUDIENCESELECTOR_POSITION, const wxSize& size = SYMBOL_AUDIENCESELECTOR_SIZE, long style = SYMBOL_AUDIENCESELECTOR_STYLE)
	{
		Me = std::dynamic_pointer_cast<AudienceSelector>(_me.lock());

		////@begin AudienceSelector creation
		SetExtraStyle(wxWS_EX_VALIDATE_RECURSIVELY | wxWS_EX_BLOCK_EVENTS);
		wxDialog::Create(parent, id, caption, pos, size, style);

		CreateControls();
		if (GetSizer())
		{
			GetSizer()->SetSizeHints(this);
		}
		Centre();
		////@end AudienceSelector creation
		return true;
	}

	/// Initialises member variables
	void Init()
	{
		////@begin AudienceSelector member initialisation
		cmbFavorites = NULL;
		cmbTokens = NULL;
		cmbCG = NULL;
		lstGroups = NULL;
		btnAdd = NULL;
		btnEdit = NULL;
		btnDelete = NULL;
		btnCreateFavorite = NULL;
		btnDeleteFavorite = NULL;
		btnOK = NULL;
		btnCancel = NULL;
		btnHelp = NULL;
		////@end AudienceSelector member initialisation
	}

	/// Creates the controls and sizers
	void CreateControls()
	{
		////@begin AudienceSelector content construction
		AudienceSelector* itemDialog1 = this;

		wxFlexGridSizer* itemFlexGridSizer2 = new wxFlexGridSizer(3, 1, 0, 0);
		itemDialog1->SetSizer(itemFlexGridSizer2);

		wxFlexGridSizer* itemFlexGridSizer3 = new wxFlexGridSizer(0, 2, 0, 0);
		itemFlexGridSizer2->Add(itemFlexGridSizer3, 0, wxGROW | wxALIGN_CENTER_VERTICAL | wxALL, 0);

		wxStaticText* itemStaticText4 = new wxStaticText(itemDialog1, wxID_STATIC, _("Favorites:"), wxDefaultPosition, wxDefaultSize, 0);
		itemFlexGridSizer3->Add(itemStaticText4, 0, wxALIGN_CENTER_HORIZONTAL | wxALIGN_CENTER_VERTICAL | wxLEFT | wxRIGHT | wxTOP, 5);

		wxArrayString cmbFavoritesStrings;
		cmbFavorites = new wxChoice(itemDialog1, ID_FAVORITELIST, wxDefaultPosition, wxSize(400, -1), cmbFavoritesStrings, 0);
		itemFlexGridSizer3->Add(cmbFavorites, 0, wxGROW | wxALIGN_CENTER_VERTICAL | wxRIGHT | wxTOP, 5);

		itemFlexGridSizer3->AddGrowableCol(0);

		wxStaticBox* itemStaticBoxSizer6Static = new wxStaticBox(itemDialog1, wxID_ANY, _("Group Access Rights"));
		wxStaticBoxSizer* itemStaticBoxSizer6 = new wxStaticBoxSizer(itemStaticBoxSizer6Static, wxVERTICAL);
		itemFlexGridSizer2->Add(itemStaticBoxSizer6, 0, wxGROW | wxLEFT | wxRIGHT | wxTOP, 5);

		wxFlexGridSizer* itemFlexGridSizer7 = new wxFlexGridSizer(0, 4, 0, 0);
		itemStaticBoxSizer6->Add(itemFlexGridSizer7, 0, wxGROW, 5);

		wxStaticText* itemStaticText8 = new wxStaticText(itemStaticBoxSizer6->GetStaticBox(), wxID_STATIC, _("Token:"), wxDefaultPosition, wxDefaultSize, 0);
		itemFlexGridSizer7->Add(itemStaticText8, 0, wxALIGN_CENTER_HORIZONTAL | wxALIGN_CENTER_VERTICAL | wxALL, 0);

		wxArrayString cmbTokensStrings;
		cmbTokens = new wxChoice(itemStaticBoxSizer6->GetStaticBox(), ID_TOKENLIST, wxDefaultPosition, wxDefaultSize, cmbTokensStrings, 0);
		itemFlexGridSizer7->Add(cmbTokens, 0, wxGROW | wxALIGN_CENTER_VERTICAL | wxALL, 0);

		wxStaticText* itemStaticText10 = new wxStaticText(itemStaticBoxSizer6->GetStaticBox(), wxID_STATIC, _("CryptoGroup:"), wxDefaultPosition, wxDefaultSize, 0);
		itemFlexGridSizer7->Add(itemStaticText10, 0, wxALIGN_CENTER_HORIZONTAL | wxALIGN_CENTER_VERTICAL | wxLEFT, 5);

		wxArrayString cmbCGStrings;
		cmbCG = new wxChoice(itemStaticBoxSizer6->GetStaticBox(), ID_CGLIST, wxDefaultPosition, wxDefaultSize, cmbCGStrings, 0);
		itemFlexGridSizer7->Add(cmbCG, 0, wxGROW | wxALIGN_CENTER_VERTICAL | wxALL, 0);

		itemFlexGridSizer7->AddGrowableCol(1);
		itemFlexGridSizer7->AddGrowableCol(3);

		wxFlexGridSizer* itemFlexGridSizer12 = new wxFlexGridSizer(0, 2, 0, 0);
		itemStaticBoxSizer6->Add(itemFlexGridSizer12, 0, wxGROW | wxALL, 0);

		wxArrayString lstGroupsStrings;
		lstGroups = new wxListBox(itemStaticBoxSizer6->GetStaticBox(), ID_LISTBOX, wxDefaultPosition, wxSize(-1, 215), lstGroupsStrings, wxLB_SINGLE);
		itemFlexGridSizer12->Add(lstGroups, 0, wxGROW | wxALL, 5);

		wxFlexGridSizer* itemFlexGridSizer14 = new wxFlexGridSizer(4, 1, 0, 0);
		itemFlexGridSizer12->Add(itemFlexGridSizer14, 0, wxGROW | wxALL, 5);

		btnAdd = new wxButton(itemStaticBoxSizer6->GetStaticBox(), ID_ADD, _("&Add"), wxDefaultPosition, wxDefaultSize, 0);
		itemFlexGridSizer14->Add(btnAdd, 0, wxALIGN_CENTER_HORIZONTAL | wxALIGN_CENTER_VERTICAL | wxALL, 0);

		btnEdit = new wxButton(itemStaticBoxSizer6->GetStaticBox(), ID_EDIT, _("&Edit"), wxDefaultPosition, wxDefaultSize, 0);
		itemFlexGridSizer14->Add(btnEdit, 0, wxALIGN_CENTER_HORIZONTAL | wxALIGN_CENTER_VERTICAL | wxALL, 0);

		btnDelete = new wxButton(itemStaticBoxSizer6->GetStaticBox(), ID_DELETE, _("&Delete"), wxDefaultPosition, wxDefaultSize, 0);
		itemFlexGridSizer14->Add(btnDelete, 0, wxALIGN_CENTER_HORIZONTAL | wxALIGN_CENTER_VERTICAL | wxALL, 0);

		itemFlexGridSizer14->Add(5, 5, 0, wxALIGN_CENTER_HORIZONTAL | wxGROW | wxALL, 5);

		itemFlexGridSizer14->AddGrowableRow(3);

		itemFlexGridSizer12->AddGrowableRow(0);
		itemFlexGridSizer12->AddGrowableCol(0);

		wxFlexGridSizer* itemFlexGridSizer19 = new wxFlexGridSizer(1, 3, 0, 0);
		itemFlexGridSizer2->Add(itemFlexGridSizer19, 0, wxALIGN_CENTER_HORIZONTAL | wxALIGN_CENTER_VERTICAL | wxALL, 5);

		wxBoxSizer* itemBoxSizer20 = new wxBoxSizer(wxHORIZONTAL);
		itemFlexGridSizer19->Add(itemBoxSizer20, 0, wxALIGN_LEFT | wxALIGN_CENTER_VERTICAL | wxALL, 5);

		btnCreateFavorite = new wxButton(itemDialog1, ID_CREATE_FAVORITE, _("Create &Favorite"), wxDefaultPosition, wxDefaultSize, 0);
		itemBoxSizer20->Add(btnCreateFavorite, 0, wxALIGN_CENTER_VERTICAL, 5);

		btnDeleteFavorite = new wxButton(itemDialog1, ID_DELETE_FAVORITE, _("Delete Favorite"), wxDefaultPosition, wxDefaultSize, 0);
		itemBoxSizer20->Add(btnDeleteFavorite, 0, wxALIGN_CENTER_VERTICAL, 5);

		itemFlexGridSizer19->Add(5, 5, 0, wxALIGN_CENTER_HORIZONTAL | wxALIGN_CENTER_VERTICAL | wxALL, 5);

		wxStdDialogButtonSizer* itemStdDialogButtonSizer24 = new wxStdDialogButtonSizer;

		itemFlexGridSizer19->Add(itemStdDialogButtonSizer24, 0, wxALIGN_CENTER_HORIZONTAL | wxALIGN_CENTER_VERTICAL | wxALL, 5);
		btnOK = new wxButton(itemDialog1, wxID_OK, _("&OK"), wxDefaultPosition, wxDefaultSize, 0);
		btnOK->SetDefault();
		itemStdDialogButtonSizer24->AddButton(btnOK);

		btnCancel = new wxButton(itemDialog1, wxID_CANCEL, _("&Cancel"), wxDefaultPosition, wxDefaultSize, 0);
		itemStdDialogButtonSizer24->AddButton(btnCancel);

		btnHelp = new wxButton(itemDialog1, wxID_HELP, _("&Help"), wxDefaultPosition, wxDefaultSize, 0);
		itemStdDialogButtonSizer24->AddButton(btnHelp);

		itemStdDialogButtonSizer24->Realize();

		itemFlexGridSizer19->AddGrowableCol(1);

		itemFlexGridSizer2->AddGrowableRow(1);
		itemFlexGridSizer2->AddGrowableCol(0);

		////@end AudienceSelector content construction
	}

	/*
	 * Should we show tooltips?
	 */
	bool AudienceSelector::ShowToolTips()
	{
		return true;
	}

	////@begin AudienceSelector event handler declarations

	/// wxEVT_COMMAND_CHOICE_SELECTED event handler for ID_FAVORITELIST
	void OnFavoritelistSelected(wxCommandEvent& event)
	{
		int favIndex;
		std::shared_ptr<IFavorite> fav;
		tscrypto::tsCryptoString name;
		GUID id = GUID_NULL;
		LRESULT idx = CB_ERR;

		// Verify that the user wishes to eliminate any previously displayed access groups.
		name.resize(512);

		// First see if we are truly setting a favorite

		favIndex = cmbFavorites->GetSelection();
		if (0 >= favIndex) {
			cmbFavorites->SetSelection(0);
			_CurFavIndex = 0;
			UpdateDialogControls();
			EnableDisableOK();
			return;
		}
		// See if the favorite has changed
		if (_CurFavIndex == favIndex)
		{
			EnableDisableOK();
			return;
		}

		idx = (int)(intptr_t)cmbFavorites->GetClientData(favIndex);
		if (idx >= 0 && idx < (LRESULT)_guidMap.size())
		{
			id = _guidMap[idx];
		}

		size_t accessGroupCount = 0;
		{
			std::shared_ptr<ICmsHeaderExtension> ext;
			std::shared_ptr<ICmsHeaderAccessGroupExtension> groupList;

			if (!_header->GetProtectedExtensionByOID(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), ext) ||
				!(groupList = std::dynamic_pointer_cast<ICmsHeaderAccessGroupExtension>(ext)))
			{
			}
			else
				accessGroupCount = groupList->GetAccessGroupCount();
		}

		if (lstGroups->GetCount() > 0)
		{
			name = lstGroups->GetStringSelection().mbc_str();
		}

		// TODO:  Reenable the last term once we implement PKI
		if (name.size() > 0 && TsStrCmp(name, AS_SEL_DOM_STR) != 0 && accessGroupCount > 0)// || mySelectedCertVector.size() > 0)
		{
			//UINT nResponse = ::MessageBox(_hDlg, "Selecting a favorite will cause all current Attribute and certificate selections to be lost.\n\n Do you wish to continue?", "Warning", MB_YESNO | MB_ICONINFORMATION);
			UINT nResponse = ::wxMessageBox("Selecting a favorite will cause all current Attribute selections to be lost.\n\n Do you wish to continue?", "Warning", MB_YESNO | MB_ICONINFORMATION);

			if (nResponse != wxID_YES)
			{
				/* Reset the favorite index before returning. */
				cmbFavorites->SetSelection(_CurFavIndex);
				return;
			}
		}

		// unset the stored Favorite
		_favorite.reset();

		/* Set the current favorite index to keep track of previous selections. */
		_CurFavIndex = favIndex;

		// deselect the favorite in case we can't switch to it
		// we will reselect it at the end if possible
		cmbFavorites->SetSelection(0);
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
				wxMessageBox("Error! Invalid favorite pointer in selection.", "Error", MB_ICONHAND | MB_OK);
			return;
		}

		// empty out the old attribute and cert lists
		/* Must loop through and delete all access groups in the grouplist control that we have stored
		previously. */
		lstGroups->Clear();
		AddGroupText(AS_SEL_DOM_STR);
		lstGroups->Enable(false);

		// TODO:  Implement when PKI supported
		//    mySelectedCertVector.clear();
		//SendMessage(_CryptoGroupCombo, CB_RESETCONTENT, 0, 0);
		//SendMessage(_CryptoGroupCombo, CB_SETCURSEL, (WPARAM)(-1), 0);

		UpdateDialogControls();
		EnableDisableOK();

		//Check if Token not present in the Slot
		int ind = cmbTokens->GetSelection();
		if (ind >= 0)
		{
			if (!Session())
			{
				CryptoGroupPressLogin();
			}
		}

		std::shared_ptr<ICmsHeader> newHeader;
		tscrypto::tsCryptoData headData(fav->headerData());

		if (!(newHeader = ::TopServiceLocator()->get_instance<ICmsHeader>("/CmsHeader")))
		{
			wxMessageBox("Unable to edit... Unable to create a CMS Header.", "Error", MB_ICONHAND | MB_OK);
			return;
		}

		if (!newHeader->IsProbableHeader(headData.c_str(), headData.size()))
		{
			wxMessageBox("The selected favorite does not contain a valid CMS header.", "Error", MB_ICONHAND | MB_OK);
			return;
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
				UINT nResponse = wxID_YES;

				if (HasSession())
				{
					nResponse = ::wxMessageBox("The Token does not contain the proper CryptoGroup or Attributes needed for the Favorite.\nDo you want to select another Token? ", "Warning", MB_YESNO | MB_ICONQUESTION);
				}
				if (nResponse == wxID_YES)
				{
					std::shared_ptr<ICmsHeaderCryptoGroup> hCG;
					std::shared_ptr<ICmsHeader> head7;
					std::shared_ptr<IKeyVEILSession> sess;

					if (!!(head7 = ::TopServiceLocator()->try_get_instance<ICmsHeader>("/CmsHeader")) && head7->FromBytes(fav->headerData()))
					{
						if (head7->GetCryptoGroupCount() == 1 && (head7->GetCryptoGroup(0, hCG)))
						{
							GUID enterpriseOid = GUID_NULL;
							std::shared_ptr<ITokenSelector> tokSel = ::TopServiceLocator()->get_instance<ITokenSelector>("/WxWin/TokenSelector");

							head7->GetEnterpriseGuid(enterpriseOid);

							if (tokSel->Start(_connector, enterpriseOid, "Select a token for the favorite", (XP_WINDOW)this) && tokSel->DisplayModal() == wxID_OK && !!(sess = tokSel->Session()))
							{
								int tokIndex = FindTokenOnComboBox(sess->GetProfile()->get_SerialNumber());

								if (tokIndex >= 0)
								{
									Session(sess);
									if (CheckLogin())
									{
										cmbTokens->SetSelection(tokIndex);
										//if (!!_session)
										//	_session->Close();
									}
									else
									{
										Session(nullptr);
									}
								}
								else
								{
									return;
								}
							}
							else
								return;
						}
						else
							return;
					}
					else
						return;
				}
				else     //user does not want to select another Token
				{
					return;
				}
			}
		} while (!bLoaded);

		// TODO:  Implement me
		//    // set this new favorite as the "default"
		//    if (myRememberFavorite)
		//        myFavs.SetDefaultFavorite(fav->favName);

		// remember the name in case we have to build an audience
		_favorite = fav;

		cmbFavorites->SetSelection(favIndex);
		_CurFavIndex = favIndex;
		EnableDisableOK();

		RebuildAccessGroupList();
		return;
	}

	/// wxEVT_COMMAND_CHOICE_SELECTED event handler for ID_TOKENLIST
	void OnTokenlistSelected(wxCommandEvent& event)
	{
		// if the programmer has specified an initial token, and a reason
		// not to change it, we won't allow the user to switch to a new token
		//if (myInitialToken != NULL && myNoChangeTokenReason.GetLength()) {
		if (!!HasSession() && Session()->IsValid())
		{
			int tokindex = 0;
			std::shared_ptr<IKeyVEILSession> tempSession;
			//        CKMToken* pTempToken = NULL;

			// first get the user's selection
			tokindex = (int)cmbTokens->GetSelection();
			if (CB_ERR != tokindex)
			{
				int index = (int)(intptr_t)cmbTokens->GetClientData(tokindex);

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

						lstGroups->Enable(false);

						EnableDisableOK();

						cmbCG->Clear();
						cmbCG->AppendString(AS_SEL_DOM_STR);
						cmbCG->AppendString(AS_SEL_DOM_STR);
						cmbCG->SetSelection(0);

						_ActiveCryptoGroup = nullptr;

						//if (!!_session)
						//	_session->Close();
						Session(nullptr);
						cmbTokens->SetFocus();
						return;
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
			if (HasSession() && tempSession->GetProfile()->get_SerialNumber() == Session()->GetProfile()->get_SerialNumber())
			{
				return;
			}

			if (!tempSession->IsLoggedIn())
			{
				if (!CheckLogin())
				{
					cmbTokens->SetSelection(-1);
					Session(nullptr);
					return;
				}
			}

			// Let the user know that any currently selected attributes will
			// be lost by selecting a new token.
			if (!QueryAndClearAccessGroups())
			{
				return;
			}
		}


		if (!ChangeToken())
			return;

		if (cmbCG->GetCount() > 1)
		{
			//_CryptoGroupCombo.SetFocus();
			//_CryptoGroupCombo.ShowDropDown();
			// added because a bug in MFC sometimes hides the cursor
			//SetCursor(LoadCursor(NULL, IDC_ARROW));
		}
		else
		{
			cmbCG->SetSelection(0);
		}

		UpdateDialogControls();
		return;
	}

	/// wxEVT_COMMAND_CHOICE_SELECTED event handler for ID_CGLIST
	void OnCglistSelected(wxCommandEvent& event)
	{
		int index;
		Asn1::CTS::_POD_CryptoGroup* tempCryptoGroup;

		// return if no CryptoGroup is selected
		index = (int)cmbCG->GetSelection();
		if (-1 == index)
		{
			return;
		}

		if (!HasSession() || !HasProfile())
		{
			wxMessageBox("Invalid Token! Unable to change CryptoGroups.", "Error", MB_ICONHAND | MB_OK);
			return;
		}

		// get the selected CryptoGroup object
		int itemIndex = (int)(intptr_t)cmbCG->GetClientData(index);
		if (itemIndex < 0 || itemIndex >= (int)GetProfile()->get_cryptoGroupList()->size() ||
			!(tempCryptoGroup = &GetProfile()->get_cryptoGroupList()->get_at(itemIndex)))
		{
			//        MessageBox(_hDlg, "Invalid CryptoGroup object! Unable to change Crypto Groups.", "Error", MB_ICONHAND | MB_OK);
			return;
		}

		// If the cryptogroup has not actually changed, do nothing.
		if (!!_ActiveCryptoGroup && (_ActiveCryptoGroup->get_Id() == tempCryptoGroup->get_Id()))
		{
			return;
		}

		/* Need to post warning telling user that the selected AGs will be lost if the CryptoGroup is changed.
		Only do this if AGs are currently selected.  If the user presses cancel, do nothing, otherwise
		post login window and continue with clearing of AG box and populating the CryptoGroup list. */
		if (!QueryAndClearAccessGroups())
		{
			return;
		}

		// clear the group list
		ClearAccessGroups();
		lstGroups->Enable(false);

		// return if no token is selected
		if (!HasSession())
			return;

		/* Verify we are logged in or log in to the currently selected token. */
		if (FALSE == CheckLogin())
		{
			cmbTokens->SetSelection(-1);
			Session(nullptr);
			//myActiveToken = NULL;
			AddGroupText(AS_SEL_DOM_STR);
			return;
		}

		// store the CryptoGroup object
		_ActiveCryptoGroup = tempCryptoGroup;

		//
		// At this point we need to update the header CryptoGroup and enterprise information.
		//
		GUID cryptoGroupGuid = { 0, };
		GUID enterpriseGuid = { 0, };
		GUID memberGuid = { 0, };
		std::shared_ptr<Asn1::CTS::_POD_Profile> profile;

		//if ( !header )
		//{
		_header = ::TopServiceLocator()->try_get_instance<ICmsHeader>("/CmsHeader");
		if (!_header)
		{
			wxMessageBox("OnChangeCryptoGroup: Unable to create a CKM Header.", "Error", MB_ICONHAND | MB_OK);
			return;
		}
		//	}

		if (!!_header)
		{
			int domIndex;

			_header->Clear();
			profile = GetProfile();
			if (!!profile)
			{
				enterpriseGuid = profile->get_EnterpriseId();
				memberGuid = profile->get_MemberId();
			}
			cryptoGroupGuid = _ActiveCryptoGroup->get_Id();
			_header->SetEnterpriseGuid(enterpriseGuid);
			_header->SetCreatorGuid(memberGuid);
			if ((_header->AddCryptoGroup(cryptoGroupGuid, &domIndex)))
			{
				//			hFief->SetUniqueNumber(1);
			}
		}
		// TODO:  Saved for when we need to filter attributes
#if 0
		tscrypto::tsCryptoData domPolStr, attrPolStr;
		CK_RV rc;
		TS_FIEFDOM_POLICY_PTR pFiefPol = NULL;

		/* We need the fiefdom policy in case an attribute is expired.  The fie policy will tell us
		whether we should list it anyway. */
		domPolStr = _ActiveCryptoGroup->getPolicy();
		pFiefPol = (TS_FIEFDOM_POLICY_PTR)domPolStr.data();

		myTokenAttrVector = new CKMVector<CKMO_Attribute>;
		for (CKMVector<CKMO_Attribute>::iterator iter = pTempAttrVect->begin(); iter != pTempAttrVect->end(); iter++)
		{
			/* Get the attributes policy.  This includes information on expire and issue dates. Then
			call the check attr function which will validate the dates. */
			attrPolStr = iter->getPolicy();
			rc = iCheckAttributePolicy(pFiefPol, (TS_ATTRIBUTE_POLICY_PTR)attrPolStr.data());

			if (rc == CKR_ATTR_ISSUED_IN_FUTURE || rc == CKR_ATTR_EXPIRED)
			{
				/* If the fiefdom policy indicates that a "negative" action should take place,
				don't list the attribute. */
				if (pFiefPol->expireAction == TS_ACTION_FAIL ||
					pFiefPol->expireAction == TS_ACTION_DESTROY)
				{
					continue;
				}
			}

			/* If the above if statement didn't skip this code, that means the fiefdom was time valid or
			the TS_ACTION was TS_ACTION_NONE. Add the attribute to the vector. */
			myTokenAttrVector->push_back(*iter);
		}
		delete pTempAttrVect;
		pTempAttrVect = NULL;

		// set the categories so the tool tips work
		_GroupCtrl.SetCatList(myTokenCatVector);
#endif

		// unset any selected favorite
		cmbFavorites->SetSelection(0);
		_favorite.reset();

		/* If still don't have a cryptoGroup, put "Select a CryptoGroup..." back into AG list box. */
		if (!_ActiveCryptoGroup)
		{
			AddGroupText(AS_SEL_DOM_STR);
		}
		else
		{
			lstGroups->Enable(true);
		}

		UpdateDialogControls();
		return;
	}

    /// wxEVT_COMMAND_LISTBOX_SELECTED event handler for ID_LISTBOX
	void OnListboxSelected(wxCommandEvent& event)
	{
		UpdateDialogControls();
	}

	/// wxEVT_COMMAND_LISTBOX_DOUBLECLICKED event handler for ID_LISTBOX
	void OnListboxDoubleClicked(wxCommandEvent& event)
	{
		OnEditClick(event);
	}

	/// wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_ADD
	void OnAddClick(wxCommandEvent& event)
	{
		// if nothing is selected, display an error
		if (cmbTokens->GetSelection() < 0)
		{
			return;
		}

		// make sure we are logged in to the selected token
		if (FALSE == CheckLogin())
		{
			cmbTokens->SetSelection(-1);
			Session(nullptr);
			//myActiveToken = NULL;
			return;
		}

		// make sure we have the CryptoGroup object
		if (_ActiveCryptoGroup == nullptr)
		{
			wxMessageBox("OnGroupAdd: No Crypto Group selected, or selected Crypto Group is invalid.", "Error", MB_ICONHAND | MB_OK);
			return;
		}

		if (!_header)
		{
			//ConstructHeader();
			//if (!_header)
			return;
		}

		std::shared_ptr<ICmsHeaderAccessGroup> andGroup;
		std::shared_ptr<ICmsHeaderAttributeGroup> attrGroup;
		std::shared_ptr<ICmsHeaderExtension> ext;
		std::shared_ptr<ICmsHeaderAccessGroupExtension> groupList;

		if (!_header->GetProtectedExtensionByOID(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), ext))
		{
			if (!_header->AddProtectedExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), true, ext))
			{
				wxMessageBox("OnGroupAdd: Unable to add a new access group list to the CKM Header.", "Error", MB_ICONHAND | MB_OK);
				return;
			}
		}
		if (!(groupList = std::dynamic_pointer_cast<ICmsHeaderAccessGroupExtension>(ext)))
		{
			return;
		}
		ext.reset();

		if (!(groupList->AddAccessGroup(ag_Attrs, andGroup)) || !(attrGroup = std::dynamic_pointer_cast<ICmsHeaderAttributeGroup>(andGroup)))
		{
			wxMessageBox("OnGroupAdd: Unable to add a new attribute list to the CKM Header.", "Error", MB_ICONHAND | MB_OK);
			if (!!andGroup)
			{
				groupList->RemoveAccessGroup(groupList->GetAccessGroupCount() - 1);
				andGroup.reset();
			}
			return;
		}

		std::shared_ptr<ICmsHeaderAttributeListExtension> attrList;

		if (!_header->GetProtectedExtensionByOID(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ATTRIBUTELIST_EXT_OID, tscrypto::tsCryptoData::OID), ext))
		{
			if (!_header->AddProtectedExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ATTRIBUTELIST_EXT_OID, tscrypto::tsCryptoData::OID), true, ext))
			{
				wxMessageBox("OnGroupAdd: Unable to add a new attribute list to the CKM Header.", "Error", MB_ICONHAND | MB_OK);
				return;
			}
		}

		if (!(attrList = std::dynamic_pointer_cast<ICmsHeaderAttributeListExtension>(ext)))
		{
			wxMessageBox("OnGroupAdd: Unable to add a new attribute list to the CKM Header.", "Error", MB_ICONHAND | MB_OK);
			return;
		}
		ext.reset();

		std::shared_ptr<IAttributeSelector> attrSel;

		if (!(attrSel = ::TopServiceLocator()->get_instance<IAttributeSelector>("/WxWin/AttributeSelectorGrid")))
		{
			attrGroup.reset();
			groupList->RemoveAccessGroup(groupList->GetAccessGroupCount() - 1);
			andGroup.reset();
		}
		else
		{
			if (!attrSel->Start(Session(), (XP_WINDOW)this, _ActiveCryptoGroup->get_Id(), attrGroup, attrList) || attrSel->DisplayModal() != wxID_OK)
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
				wxMessageBox("You already have an access group with the same Attributes.", "Error", MB_ICONHAND | MB_OK);
				return;
			}
		}
		RebuildAccessGroupList();

		EnableDisableOK();
		return;
	}

	/// wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_EDIT
	void OnEditClick(wxCommandEvent& event)
	{
		int index;

		std::shared_ptr<ICmsHeaderAttributeGroup> attrs;
		std::shared_ptr<ICmsHeaderAccessGroup> accessGroup;

		index = lstGroups->GetSelection();
		if (-1 == index) {
			wxMessageBox("Unable to edit... No access group is selected.", "Error", MB_ICONHAND | MB_OK);
			return;
		}

		if (!FindSelectedAccessGroup(accessGroup, attrs))
		{
			wxMessageBox("Unable to edit... The selected access group was not located.", "Error", MB_ICONHAND | MB_OK);
			return;
		}

		std::shared_ptr<ICmsHeader> newHeader;

		if (!(newHeader = ::TopServiceLocator()->get_instance<ICmsHeader>("/CmsHeader")))
		{
			wxMessageBox("Unable to edit... Unable to create a CKM Header.", "Error", MB_ICONHAND | MB_OK);
			return;
		}

		std::shared_ptr<ICmsHeaderAccessGroup> andGroup;
		std::shared_ptr<ICmsHeaderAttributeGroup> attrGroup;
		std::shared_ptr<ICmsHeaderExtension> ext;
		std::shared_ptr<ICmsHeaderAccessGroupExtension> extGroup;

		if (!newHeader->GetProtectedExtensionByOID(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), ext))
		{
			newHeader->AddProtectedExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), true, ext);
		}

		if (!ext || !(extGroup = std::dynamic_pointer_cast<ICmsHeaderAccessGroupExtension>(ext)))
		{
			wxMessageBox("Unable to delete... The access group list is not available.", "Error", MB_ICONHAND | MB_OK);
			return;
		}
		ext.reset();

		if (!(extGroup->AddAccessGroup(ag_Attrs, andGroup)) || !(attrGroup = std::dynamic_pointer_cast<ICmsHeaderAttributeGroup>(andGroup)))
		{
			wxMessageBox("Unable to edit... Unable to add a new attribute list to the CKM Header.", "Error", MB_ICONHAND | MB_OK);
			return;
		}
		int count = (int)attrs->GetAttributeCount();
		for (int i = 0; i < count; i++)
		{
			attrGroup->AddAttributeIndex(attrs->GetAttributeIndex(i));
		}

		std::shared_ptr<ICmsHeaderAttributeListExtension> attrsList;

		if (!_header->GetProtectedExtensionByOID(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ATTRIBUTELIST_EXT_OID, tscrypto::tsCryptoData::OID), ext))
		{
			if (!_header->AddProtectedExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ATTRIBUTELIST_EXT_OID, tscrypto::tsCryptoData::OID), true, ext))
			{
				wxMessageBox("Unable to edit... Unable to retrieve the attribute list.", "Error", MB_ICONHAND | MB_OK);
				return;
			}
		}

		if (!(attrsList = std::dynamic_pointer_cast<ICmsHeaderAttributeListExtension>(ext)))
		{
			wxMessageBox("Unable to edit... Unable to retrieve the attribute list.", "Error", MB_ICONHAND | MB_OK);
			return;
		}
		ext.reset();

		std::shared_ptr<IAttributeSelector> attrSel;

		if (!(attrSel = ::TopServiceLocator()->get_instance<IAttributeSelector>("/WxWin/AttributeSelectorGrid")))
		{
			return;
		}
		if (!attrSel->Start(Session(), (XP_WINDOW)this, _ActiveCryptoGroup->get_Id(), attrGroup, attrsList) || attrSel->DisplayModal() != wxID_OK)
		{
			return;
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

		return;
	}

	/// wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_DELETE
	void OnDeleteClick(wxCommandEvent& event)
	{
		int index;

		index = lstGroups->GetSelection();
		if (-1 == index)
		{
			wxMessageBox("Unable to delete... No access group is selected.", "Error", MB_ICONHAND | MB_OK);
			return;
		}

		std::shared_ptr<ICmsHeaderExtension> ext;
		std::shared_ptr<ICmsHeaderAccessGroupExtension> extGroup;
		std::shared_ptr<ICmsHeaderAccessGroup> andGroup;

		if (!_header->GetProtectedExtensionByOID(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), ext) ||
			!(extGroup = std::dynamic_pointer_cast<ICmsHeaderAccessGroupExtension>(ext)))
		{
			wxMessageBox("Unable to delete... The access group list is not available.", "Error", MB_ICONHAND | MB_OK);
			return;
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
						wxMessageBox("Unable to delete... The selected access group was not located.", "Error", MB_ICONHAND | MB_OK);
						return;
					}
					lstGroups->Delete(index);
				}
				index--;
			}
		}

		RebuildAccessGroupList();

		// remove the access group from the display list,
		SetItemSelected(index);
		UpdateDialogControls();
		EnableDisableOK();

		return;
	}

	/// wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_CREATE_FAVORITE
	void OnCreateFavoriteClick(wxCommandEvent& event)
	{
		std::shared_ptr<ICmsHeaderExtension> ext;
		std::shared_ptr<ICmsHeaderAccessGroupExtension> groupList;

		if (!_header->GetProtectedExtensionByOID(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), ext) ||
			!(groupList = std::dynamic_pointer_cast<ICmsHeaderAccessGroupExtension>(ext)) || groupList->GetAccessGroupCount() == 0)
		{
			wxMessageBox("No access groups have been created.", "Error", MB_ICONHAND | MB_OK);
			return;
		}

		GUID id = GUID_NULL;

		if (_CurFavIndex == 0)
		{
			tscrypto::tsCryptoString favName;
			std::shared_ptr<IFavoriteName> dlg = ::TopServiceLocator()->get_instance<IFavoriteName>("/WxWin/FavoriteName");

			if (!dlg || !dlg->Start((XP_WINDOW)this) || dlg->DisplayModal() != wxID_OK)
				return;

			favName = dlg->Name();
			id = _connector->CreateFavorite(GetProfile()->get_SerialNumber(), _header->ToBytes(), favName);
			if (id == GUID_NULL)
			{
				wxMessageBox("An error occurred while attempting to create the new favorite.", "Error", MB_ICONHAND | MB_OK);
				return;
			}
			if (cmbFavorites->FindString(favName.c_str()) < 0)
			{
				cmbFavorites->Append(favName.c_str(), (void*)(intptr_t)findGuidIndex(id, true));
			}
			return;
		}
		else
		{
			int idx = (int)(intptr_t)cmbFavorites->GetClientData(_CurFavIndex);

			if (idx >= 0 && idx < (LRESULT)_guidMap.size())
			{
				id = _guidMap[idx];
			}
		}

		if (id != GUID_NULL)
		{
			if (!_connector->UpdateFavorite(id, _header->ToBytes()))
			{
				wxMessageBox("An error has occurred while updating the favorite.", "Error", MB_ICONHAND | MB_OK);
				return;
			}
			if (_CurFavIndex > 0)
			{
				wxMessageBox("The favorite has been updated.", "Updated", MB_OK);
			}
		}
		else
		{
			wxMessageBox("The selected favorite could not be found.", "Error", MB_ICONHAND | MB_OK);
			return;
		}

		return;
	}

	/// wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_DELETE_FAVORITE
	void OnDeleteFavoriteClick(wxCommandEvent& event)
	{
		if (_CurFavIndex == 0)
		{
			return;
		}

		GUID id = GUID_NULL;
		int idx = (int)(intptr_t)cmbFavorites->GetClientData(_CurFavIndex);

		if (idx >= 0 && idx < (int)_guidMap.size())
		{
			id = _guidMap[idx];
		}

		if (id == GUID_NULL)
		{
			wxMessageBox("An error occurred while attempting to retrieve the favorite.", "Error", MB_ICONHAND | MB_OK);
			return;
		}
		if (!_connector->DeleteFavorite(id))
		{
			wxMessageBox("An error occurred while attempting to delete the favorite.", "Error", MB_ICONHAND | MB_OK);
			return;
		}
		_CurFavIndex = 0;
		InitFavorites();
		if (!!_header)
			_header->Clear();

		UpdateDialogControls();
		EnableDisableOK();
		return;
	}

	/// wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_OK
	void OnOkClick(wxCommandEvent& event)
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
		//       if ( wxID_CANCEL == MessageBox("The favorite selected contains at least one certificate.  Continue with selection?",
		//                                  "CKM Audience Selector Dialog",
		//                                  MB_OKCANCEL) )
		//       {
		//           /* Just return if they didn't want to continue. */
		//           return TRUE;
		//       }
		//    }

		// TODO:  Implement second term when we support PKI
		// get the number of access groups in the list
		if ((count = lstGroups->GetCount()) == 0 /*&&
																				(0 == mySelectedCertVector.size())*/) {
			wxMessageBox("You haven't selected any Groups or People.", "Error", MB_ICONHAND | MB_OK);
			event.StopPropagation();
			return;
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
		//                if (result == wxID_NO)
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
		//        if (result == wxID_CANCEL)
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

		EndDialog(wxID_OK);
		resetConsumer();
		return;
	}

	/// wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_CANCEL
	void OnCancelClick(wxCommandEvent& event)
	{
		EndDialog(wxID_CANCEL);
	}

	/// wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_HELP
	void OnHelpClick(wxCommandEvent& event)
	{
		tscrypto::tsCryptoString path;

		//if (!xp_PathSearch("CKMDesktop.chm", path))
		//{
		//	wxMessageBox(_hDlg, ("We were unable to locate the help file for the VEIL system."), ("Error"), MB_OK);
		//}
		//else
		//{
		//	TS_HtmlHelp((XP_WINDOW)_hDlg, path, HH_HELP_CONTEXT, IDH_AUDIENCE_SELECTOR);
		//}

		wxMessageBox(("Help is not available at this time."), ("Status"), MB_OK);
	}
	////@end AudienceSelector event handler declarations

	void OnInitDialog()
	{
		btnOK->Enable(false);

		/* Activate the favorite combo at first.  Will be disabled later if necessary. */
		cmbFavorites->Enable(true);

		// change controls based on settings of _CreateFavorites
		if (_CreateFavorites) {
			this->SetTitle("Manage Favorites");
			btnCancel->SetLabel("&Close");
			btnCreateFavorite->SetLabel("Create &Favorite");
			btnOK->Show(false);
		}
		else
		{
			btnDeleteFavorite->Enable(false);
			btnDeleteFavorite->Show(false);
		}

		EnableDisableOK();

		// now, select a token and login to it (after the dialog comes up)
		//PostMessage(_hDlg, WM_POSTINIT, 0, 0);
		InitSettings();
	}
	void InitSettings()
	{
		int index;
		CWaitCursor wc(this);
		tscrypto::tsCryptoString selection;

		if (InitTokenInfoList())
		{
			InitTokenComboBox();
		}
		else
		{
			LOG(DebugError, "Unable to find any Tokens.");
			_initialized = true;
			return;
		}
		AddGroupText(AS_SEL_DOM_STR);
		lstGroups->Enable(false);

		cmbCG->Clear();
		cmbCG->AppendString(AS_SEL_DOM_STR);
		cmbCG->AppendString(AS_SEL_DOM_STR);
		cmbCG->SetStringSelection(AS_SEL_DOM_STR);

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
			cmbCG->Clear();
			cmbCG->AppendString("<No Token Selected>");
			cmbCG->SetStringSelection("<No Token Selected>");
			UpdateDialogControls();
			_initialized = true;
			//SetTimer(_hDlg, 1, 500, NULL);
			return;
		}

		// TODO:  Implement me
		/*    // if we are supposed to remember favorites, load it up
		if (myRememberFavorite && selection.GetLength() &&
		(CB_ERR != _FavoriteCombo.SelectString(-1, selection)))
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
		if (cmbFavorites->GetCount() != 0)
		{
			cmbFavorites->SetFocus();
		}
		else
		{
			cmbTokens->SetFocus();
		}
		//SetTimer(_hDlg, 1, 500, NULL);
		return;
	}
	void resetConsumer()
	{
		// TODO:  Change detection needed here
		//std::shared_ptr<AS_ChangeConsumer> con = changeConsumer;

		//changeConsumer.reset();
		//if (!!con)
		//	con->Disconnect();
	}
	Asn1::CTS::_POD_CryptoGroup* GetCGbyGuid(const GUID& id)
	{
		if (!HasSession() || !HasProfile())
			return nullptr;

		for (size_t i = 0; i < GetProfile()->get_cryptoGroupList()->size(); i++)
		{
			if (GetProfile()->get_cryptoGroupList()->get_at(i).get_Id() == id)
			{
				return &GetProfile()->get_cryptoGroupList()->get_at(i);
			}
		}
		return nullptr;
	}
	int findCgByGuid(const GUID& id)
	{
		if (!HasSession() || !HasProfile() || GetProfile()->get_cryptoGroupList()->size() == 0)
			return -1;

		for (size_t i = 0; i < GetProfile()->get_cryptoGroupList()->size(); i++)
		{
			if (GetProfile()->get_cryptoGroupList()->get_at(i).get_Id() == id)
				return (int)i;
		}
		return -1;
	}
	void OnChangeCryptoGroup()
	{
		wxCommandEvent evt;
		OnCglistSelected(evt);
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
		lstGroups->Clear();
		lstGroups->Append(AS_SEL_DOM_STR);
		lstGroups->Enable(false);

		if (!HasSession() || !HasProfile() || fav->enterpriseId() != GetProfile()->get_EnterpriseId())
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
			Asn1::CTS::_POD_CryptoGroup* tempCG;
			std::shared_ptr<ICmsHeaderCryptoGroup> hCG;
			std::shared_ptr<ICmsHeader> fav_header;
			GUID cgGuid;

			// set the token selection and re-read the fiefdom list
			////_TokenCombo.SetCurSel(index); // RDBJ use the currently selected token

			CryptoGroupPressLogin();

			if (!(fav_header = ::TopServiceLocator()->try_get_instance<ICmsHeader>("/CmsHeader")))
			{
				//fav->Delete();
				cmbFavorites->SetSelection(0);
				return FALSE;
			}
			fav_header->FromBytes(fav->headerData());

			if (fav_header->GetCryptoGroupCount() > 0 && (!(fav_header->GetCryptoGroup(0, hCG))))
			{
				//fav->Delete();
				cmbFavorites->SetSelection(0);
				return FALSE;
			}
			if (!!hCG && HasSession())
			{
				cgGuid = hCG->GetCryptoGroupGuid();
				// now we have to find the proper fiefdom
				if (!!(tempCG = GetCGbyGuid(cgGuid)))
				{
					int index = findCgByGuid(cgGuid);
					int cgIndex;
					int cgCount;

					cgCount = cmbCG->GetCount();
					for (cgIndex = 0; cgIndex < cgCount; cgIndex++)
					{
						if (index == (int)(intptr_t)cmbCG->GetClientData(cgIndex))
						{
							cmbCG->SetSelection(cgIndex);
							break;
						}
					}
					if (cgIndex >= cgCount)
					{
						cmbCG->SetSelection(-1);
					}
				}

				OnChangeCryptoGroup();

				// Verify we are logged in or log in to the currently selected token.
				if (!CheckLogin())
				{
					cmbTokens->SetSelection(-1);
					Session(nullptr);
					return FALSE;
				}
			}
			else
			{
				cmbCG->SetSelection(-1);
				OnChangeCryptoGroup();
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
	void ClearAccessGroups()
	{
		/* Clear group control box and all ag lists. */
		if (!!_header)
		{
			_header->RemoveExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID));
			_header->RemoveExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ATTRIBUTELIST_EXT_OID, tscrypto::tsCryptoData::OID));
		}

		lstGroups->Clear();
	}
	tscrypto::tsCryptoString BuildAttrsLine(std::shared_ptr<ICmsHeaderAttributeGroup> attrs)
	{
		int index, idx;
		int count;
		GUID id;
		Asn1::CTS::_POD_Attribute* attr;
		std::shared_ptr<ICmsHeaderAttribute> headerAttr;
		std::shared_ptr<ICmsHeaderAttributeListExtension> attrList;
		std::shared_ptr<ICmsHeaderExtension> ext;
		tscrypto::tsCryptoString name;
		tscrypto::tsCryptoString list;

		if (!_header->GetProtectedExtensionByOID(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ATTRIBUTELIST_EXT_OID, tscrypto::tsCryptoData::OID), ext) ||
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
				id = headerAttr->GetAttributeGUID();

				attr = _ActiveCryptoGroup->get_AttributeById(id);
				if (!!attr)
				{
					name = attr->get_Name();
					if (name.size() == 0)
					{
						name.Format("<attr %s>", TSGuidToString(id).c_str());
					}
				}
				else
				{
					name.Format("<attr %s>", TSGuidToString(id).c_str());
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
			int index;

			sel = (int)lstGroups->GetSelection();
			lstGroups->Clear();

			std::shared_ptr<ICmsHeaderExtension> ext;
			std::shared_ptr<ICmsHeaderAccessGroupExtension> extGroup;
			if (!_header->GetProtectedExtensionByOID(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), ext))
			{
				_header->AddProtectedExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), true, ext);
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

			if (sel < 0 || sel >= (int)lstGroups->GetCount())
			{
				sel = (int)lstGroups->GetCount() - 1;
			}
			SetItemSelected(sel);
			lstGroups->Enable(accessGroupCount > 0);
		}
		UpdateDialogControls();
		return TRUE;
	}
	void SetItemSelected(int index)
	{
		lstGroups->SetSelection(index);
	}
	void AddGroupText(const char *text)
	{
		lstGroups->Append(text);
		UpdateDialogControls();
	}
	BOOL QueryAndClearAccessGroups()
	{
		if (lstGroups->GetCount() > 0)
		{
			tscrypto::tsCryptoString name;

			name = lstGroups->GetString(0).mbc_str();
			/* If there is one item in the list and it is the text string AS_SEL_DOM_STR, don't
			pop up the warning message. */
			if (lstGroups->GetCount() != 1 || TsStrCmp(name, AS_SEL_DOM_STR) != 0)
			{
				UINT nResponse = ::wxMessageBox("Changing Tokens will cause all current Attribute selections to be lost.\n\n Do you wish to continue?", "Warning", MB_YESNO | MB_ICONINFORMATION);

				if (nResponse != wxID_YES)
				{
					// Restore the value to the prior selection
					cmbTokens->SetSelection(_LastTokenSelection);
					return FALSE;
				}
			}

			ClearAccessGroups();

			AddGroupText(AS_SEL_DOM_STR);
			lstGroups->Enable(false);
		}
		return TRUE;
	}
	//
	// when called by other functions we don't auto-select a CryptoGroup
	//
	BOOL ChangeToken()
	{
		int index;

		// return false if nothing is selected
		index = (int)cmbTokens->GetSelection();
		if (0 > index) {
			return FALSE;
		}

		// empty the CryptoGroup combo box and free any memory being used
		cmbFavorites->SetSelection(0);
		_favorite.reset();
		_CurFavIndex = 0;

		cmbCG->Clear();

		if (!!_header)
		{
			_header->RemoveExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID));
			_header->RemoveExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ATTRIBUTELIST_EXT_OID, tscrypto::tsCryptoData::OID));
		}

		/* Don't forget to clean up any existing access groups that are saved in the _GroupCtrl. */
		lstGroups->Clear();
		AddGroupText(AS_SEL_DOM_STR);
		lstGroups->Enable(false);

		EnableDisableOK();

		cmbCG->Append(AS_SEL_DOM_STR);
		cmbCG->Append(AS_SEL_DOM_STR);
		cmbCG->SetSelection(0);

		_ActiveCryptoGroup = nullptr;

		//if (!!_session)
		//	_session->Close();
		Session(nullptr);
		_header.reset();

		int idx = (int)(intptr_t)cmbTokens->GetClientData(index);
		std::shared_ptr<IToken> tok;

		if (idx >= 0 && idx < (LRESULT)_tokenSerialNumbers.size())
		{
			tok = _connector->token(_tokenSerialNumbers[idx]);
		}
		if (!tok)
		{
			tscrypto::tsCryptoString name;

			name = cmbTokens->GetString(index).mbc_str();
			name << "  Unable to change Token.";
			wxMessageBox(name.c_str(), "Error", MB_OK);
			return FALSE;
		}
		Session(tok->openSession());
		if (!HasSession())
		{
			tscrypto::tsCryptoString name;

			name = cmbTokens->GetString(index).mbc_str();
			name << "  Unable to change Token.";
			wxMessageBox(name.c_str(), "Error", MB_OK);
			return FALSE;
		}

		EnableDisableOK();

		if (HasSession())
		{
			if (!CheckLogin())
			{
				cmbTokens->SetSelection(-1);
				Session(nullptr);
			}
		}

		if (HasSession() && Session()->IsLoggedIn())
		{
			// We can select the first CryptoGroup here
			populateCryptoGroupList();
		}

		return TRUE;
	}
	void populateCryptoGroupList()
	{
		DWORD index = 0;
		//    CK_RV rc = 0;
		//    TS_FIEFDOM_POLICY_PTR pFiefPol = NULL;

		/* If no token is selected, we need to get the first one in the list. */
		//if (!_session)
		//{
		//if (SendMessage(_TokenCombo, CB_GETCURSEL, 0, 0) < 0 && SendMessage(_TokenCombo, CB_GETCOUNT, 0, 0) > 0)
		//{
		//	SendMessage(_TokenCombo, CB_SETCURSEL, 0, 0);
		//}
		//if (SendMessage(_TokenCombo, CB_GETCURSEL, 0, 0) >= 0)
		//{
		//	OnChangeTokenByControl();
		//}
		//}

		if (!HasSession())
		{
			wxMessageBox("Please select a token before attempting to select the crypto group.", "Warning", MB_ICONHAND | MB_OK);
			return;
		}

		//if (!_session->isValid())
		//{
		//	wxMessageBox(_hDlg, "The selected token is not available for use at this time.  Please select a different token.", "Warning", MB_ICONHAND | MB_OK);
		//	return FALSE;
		//}

		/* Return if login fails. */
		if (FALSE == CheckLogin())
		{
			cmbTokens->SetSelection(-1);
			Session(nullptr);
			return;
		}

		/* Populate Crypto Group combo box with list of CryptoGroups available on this token that aren't expired, etc. */
		if (!_ActiveCryptoGroup)
		{
			Asn1::CTS::_POD_CryptoGroup* cg;
			size_t cgCount;

			// TODO:  Not checking policy at this time.  Implement later
#if 0
			tscrypto::tsCryptoString ckmStr;
			tscrypto::tsCryptoData domPolStr;
			_CryptoGroupCombo.ResetContent();
			myTokenDomVector = myActiveSession->listFiefdomObjects();
			for (CKMVector<CKMO_FIEFDOM>::iterator iter = myTokenDomVector->begin(); iter != myTokenDomVector->end(); iter++)
			{
				/* If the fiefdom is time invalid and the fiefdom policy indicates we should
				care, dont display the fiefdom in the list.  Otherwise, add da sucka. */
				domPolStr = iter->getPolicy();
				pFiefPol = (TS_FIEFDOM_POLICY_PTR)domPolStr.data();
				rc = iCheckFiefdomPolicy(pFiefPol);
				if (rc == CKR_FIEFDOM_ISSUED_IN_FUTURE || rc == CKR_FIEFDOM_EXPIRED)
				{
					/* If the fiefdom policy indicates that a "negative" action should take place,
					don't list the fiefdom. */
					if (pFiefPol->expireAction == TS_ACTION_FAIL ||
						pFiefPol->expireAction == TS_ACTION_DESTROY)
					{
						continue;
					}
				}

				/* If the above if statement didn't skip this code, that means the fiefdom was time valid or
				the TS_ACTION was TS_ACTION_NONE. */
				ckmStr = iter->getLabel();
				index = _CryptoGroupCombo.AddString(ckmStr.c_str());
				_CryptoGroupCombo.SetItemDataPtr(index, &*iter);
			}
#endif
			cgCount = GetProfile()->get_cryptoGroupList()->size();

			cmbCG->Clear();
			for (index = 0; index < cgCount; index++)
			{
				cg = nullptr;
				cg = &GetProfile()->get_cryptoGroupList()->get_at(index);
				if (!!cg)
				{
					tscrypto::tsCryptoString name;

					// TODO:  Add expiration checking here

					name = cg->get_Name();
					cmbCG->Append(name.c_str(), (void*)(intptr_t)index);
				}
			}
			cmbCG->SetSelection(0);
			OnChangeCryptoGroup();
		}

		return;
	}
	int CheckLogin()
	{
		if (!HasSession())
			return FALSE;

		if (Session()->IsLoggedIn())
			return TRUE;

		std::shared_ptr<ITokenLogin> login = ::TopServiceLocator()->try_get_instance<ITokenLogin>("/WxWin/TokenLogIn");

		if (!!login)
		{
			if (!login->Start(Session(), (XP_WINDOW)this) || login->DisplayModal() != wxID_OK)
				return FALSE;
		}
		else
			return FALSE;
		return TRUE;
	}
	void UpdateDialogControls()
	{
		int index;

		// first make sure a cryptoGroup is selected
		if (!_ActiveCryptoGroup)
		{
			btnAdd->Enable(false);
			btnEdit->Enable(false);
			btnDelete->Enable(false);
		}
		else
		{
			btnAdd->Enable(true);
			// now see if a group is selected
			index = lstGroups->GetSelection();
			if (-1 == index)
			{
				btnEdit->Enable(false);
				btnDelete->Enable(false);
			}
			else
			{
				btnEdit->Enable(true);
				btnDelete->Enable(true);
			}
		}
		if (_CurFavIndex == 0)
			btnCreateFavorite->SetLabel("Create &Favorite");
		else
			btnCreateFavorite->SetLabel("Update &Favorite");
	}
	INT_PTR CryptoGroupPressLogin()
	{
		populateCryptoGroupList();
		return TRUE;
	}
	void EnableDisableOK()
	{
		int attributeCount = 0;
		BOOL bEnableOK = FALSE;
		BOOL bEnableFav = FALSE;

		attributeCount = lstGroups->GetCount();

		/* If there is more than one item in the list,...*/
		if (attributeCount > 0)
		{
			/* If there is one item and it is the "select cryptogroup" string, the box is really empty. */
			if (attributeCount == 1)
			{
				tscrypto::tsCryptoString name;

				name = lstGroups->GetString(0).mbc_str();
				if (TsStrCmp(name, AS_SEL_DOM_STR) != 0)
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
		btnOK->Enable(bEnableOK != FALSE);
		btnCreateFavorite->Enable(bEnableFav != FALSE);
		btnDeleteFavorite->Enable(_CreateFavorites && _CurFavIndex > 0);
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
		//int index;
		size_t tokenCount;
		tscrypto::tsCryptoString name;
		std::shared_ptr<IToken> token;
		tscrypto::tsCryptoData tokenSerial;

		if (HasSession() && HasProfile())
		{
			tokenSerial = GetProfile()->get_SerialNumber();
		}

		// Empty the  contents of the token combo
		cmbTokens->Clear();

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

				cmbTokens->Append(name.c_str(), (void*)serialidx);
			}
		}

		// If we have no tokens available in any slot, disable the control box.
		if (cmbTokens->GetCount() == 0)
		{
			cmbTokens->Enable(false);
		}
		if (tokenSerial.size() > 0)
		{
			int curToken = FindTokenOnComboBox(tokenSerial);
			if (curToken != CB_ERR)
				cmbTokens->SetSelection(curToken);
		}
	}
	void OnTokenAdd(const tscrypto::tsCryptoData& serialNumber)
	{
		int curToken = FindTokenOnComboBox(serialNumber);
		int cursel = cmbTokens->GetSelection();
		tscrypto::tsCryptoString name;

		if (curToken == CB_ERR)
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

				cmbTokens->Append(name.c_str(), (void*)serialidx);
			}
		}
		else
		{
			bool isSelected = (curToken == cursel);

			if (isSelected)
			{
				cmbTokens->SetSelection(-1);
			}

			int serialIndex = (int)(intptr_t)cmbTokens->GetClientData(curToken);
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
				cmbTokens->Delete(curToken);
				cmbTokens->Append(name.c_str(), (void*)(intptr_t)serialIndex);
				if (isSelected)
				{
					cmbTokens->SetStringSelection(name.c_str());

					wxCommandEvent evt;
					OnTokenlistSelected(evt);
				}
			}
		}
	}
	void OnTokenRemove(const tscrypto::tsCryptoData& serialNumber)
	{
		int curToken = FindTokenOnComboBox(serialNumber);
		int cursel = cmbTokens->GetSelection();
		char name[512];
		int nameLen = sizeof(name);

		if (curToken != CB_ERR)
		{
			bool isSelected = (curToken == cursel);

			if (isSelected)
			{
				cmbTokens->SetSelection(-1);
			}

			int serialIndex = (int)(intptr_t)cmbTokens->GetClientData(curToken);
			name[0] = 0;
			nameLen = sizeof(name);
			TsSnPrintf(name, sizeof(name), "%s%s", EMPTY_SLOT_PREFIX, EMPTY_SLOT_SUFFIX);

			cmbTokens->Delete(curToken);
			cmbTokens->Append(name, (void*)(intptr_t)serialIndex);
			if (isSelected)
			{
				cmbTokens->SetStringSelection(name);

				wxCommandEvent evt;
				OnTokenlistSelected(evt);
			}
		}
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

		if (!_header->GetProtectedExtensionByOID(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), ext) ||
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
		tscrypto::tsCryptoString name;

		if (!_header)
			return false;

		std::shared_ptr<ICmsHeaderExtension> ext;
		std::shared_ptr<ICmsHeaderAccessGroupExtension> extGroup;
		if (!_header->GetProtectedExtensionByOID(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), ext) ||
			!(extGroup = std::dynamic_pointer_cast<ICmsHeaderAccessGroupExtension>(ext)))
		{
			return false;
		}
		ext.reset();

		attrs.reset();
		accessGroup.reset();

		sel = lstGroups->GetSelection();
		name = lstGroups->GetString(sel).mbc_str();

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
				if (TsStrCmp(line, name) == 0)
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
		size_t count;
		tscrypto::tsCryptoString name;

		count = _connector->favoriteCount();

		/* If no favorites found, disable the favorite list. */
		if (count == 0)
		{
			cmbFavorites->Enable(false);
			return;
		}
		else
		{
			cmbFavorites->Enable(true);
		}

		cmbFavorites->Clear();
		for (favIndex = 0; favIndex < count; favIndex++)
		{
			fav.reset();
			if (!!(fav = _connector->favorite(favIndex)))
			{
				name = fav->favoriteName();
				if (cmbFavorites->FindString(name.c_str()) < 0)
				{
					cmbFavorites->Append(name.c_str(), (void*)(intptr_t)findGuidIndex(fav->favoriteId(), true));
				}
			}
		}
		cmbFavorites->Insert(SAVE_FAVORITE_LINE, 0);
		cmbFavorites->SetSelection(0);

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
			return CB_ERR;

		count = cmbTokens->GetCount();
		for (index = 0; index < count; index++)
		{
			ser = (int)(intptr_t)cmbTokens->GetClientData(index);
			if (ser != -1)
			{
				if (ser == serialIndex)
					return index;
			}
		}
		return CB_ERR;
	}

	////@begin AudienceSelector member function declarations

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
	////@end AudienceSelector member function declarations

private:
	////@begin AudienceSelector member variables
	wxChoice* cmbFavorites;
	wxChoice* cmbTokens;
	wxChoice* cmbCG;
	wxListBox* lstGroups;
	wxButton* btnAdd;
	wxButton* btnEdit;
	wxButton* btnDelete;
	wxButton* btnCreateFavorite;
	wxButton* btnDeleteFavorite;
	wxButton* btnOK;
	wxButton* btnCancel;
	wxButton* btnHelp;
	////@end AudienceSelector member variables
};

/*
 * AudienceSelector event table definition
 */

BEGIN_EVENT_TABLE(AudienceSelector, wxDialog)

////@begin AudienceSelector event table entries
EVT_CHOICE(ID_FAVORITELIST, AudienceSelector::OnFavoritelistSelected)
EVT_CHOICE(ID_TOKENLIST, AudienceSelector::OnTokenlistSelected)
EVT_CHOICE(ID_CGLIST, AudienceSelector::OnCglistSelected)
EVT_LISTBOX(ID_LISTBOX, AudienceSelector::OnListboxSelected)
EVT_LISTBOX_DCLICK(ID_LISTBOX, AudienceSelector::OnListboxDoubleClicked)
EVT_BUTTON(ID_ADD, AudienceSelector::OnAddClick)
EVT_BUTTON(ID_EDIT, AudienceSelector::OnEditClick)
EVT_BUTTON(ID_DELETE, AudienceSelector::OnDeleteClick)
EVT_BUTTON(ID_CREATE_FAVORITE, AudienceSelector::OnCreateFavoriteClick)
EVT_BUTTON(ID_DELETE_FAVORITE, AudienceSelector::OnDeleteFavoriteClick)
EVT_BUTTON(wxID_OK, AudienceSelector::OnOkClick)
EVT_BUTTON(wxID_CANCEL, AudienceSelector::OnCancelClick)
EVT_BUTTON(wxID_HELP, AudienceSelector::OnHelpClick)
////@end AudienceSelector event table entries

END_EVENT_TABLE()


tsmod::IObject* CreateAudienceSelector()
{
	return dynamic_cast<tsmod::IObject*>(new AudienceSelector(false));
}
tsmod::IObject* CreateFavoriteEditer()
{
	return dynamic_cast<tsmod::IObject*>(new AudienceSelector(true));
}