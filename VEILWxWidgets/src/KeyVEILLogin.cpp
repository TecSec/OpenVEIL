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

#define KEYVEIL_MIN_PIN_LEN 6
#define KEYVEIL_MAX_PIN_LEN 64

#define ID_KEYVEILLOGIN 10000
#define ID_URL 10001
#define ID_USERNAME 10002
#define ID_PASSWORD 10003
#define ID_STATUS 10007
#define SYMBOL_KEYVEILLOGIN_STYLE wxCAPTION|wxSYSTEM_MENU|wxCLOSE_BOX|wxTAB_TRAVERSAL
#define SYMBOL_KEYVEILLOGIN_TITLE _("KeyVEIL Login")
#define SYMBOL_KEYVEILLOGIN_IDNAME ID_KEYVEILLOGIN
#define SYMBOL_KEYVEILLOGIN_SIZE wxSize(400, 300)
#define SYMBOL_KEYVEILLOGIN_POSITION wxDefaultPosition

class KeyVEILLogIn : public IKeyVEILLogin, public tsmod::IObject, public wxDialog
{
	DECLARE_EVENT_TABLE()

public:
	KeyVEILLogIn() : _parent(nullptr)
	{
		Init();
	}
	virtual ~KeyVEILLogIn() {}

	// wxDialog
	virtual bool Destroy() override
	{
		_parent = XP_WINDOW_INVALID;
		_url.clear();
		_username.clear();
		_pinBuffer.clear();
		if (!!Me)
		{
			Close();
			Me.reset();
		}
		return true;
	}
	// IVEILWxUIBase
	virtual int  DisplayModal() override
	{
		if (_parent == XP_WINDOW_INVALID)
			_parent = (XP_WINDOW)wxTheApp->GetTopWindow();

		if (!_connector)
		{
			Start(nullptr, _parent);
		}

		// Construct the dialog here
		Create((wxWindow*)_parent);

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

	// IKeyVEILLogIn
	virtual bool Start(std::shared_ptr<IKeyVEILConnector> connector, XP_WINDOW parent) override
	{
		_connector = connector;
		_parent = parent;

		if (!_connector)
		{
			_connector = ::TopServiceLocator()->try_get_instance<IKeyVEILConnector>("KeyVEILConnector");
		}
		if (!_connector)
		{
			wxMessageBox("An error occurred while creating the KeyVEIL Connector.", "ERROR", MB_OK);
			return false;
		}

		return true;
	}
	virtual std::shared_ptr<IKeyVEILConnector> Connector() override
	{
		return _connector;
	}
	virtual tscrypto::tsCryptoString Pin() override
	{
		return _pinBuffer;
	}
	virtual void Pin(const tscrypto::tsCryptoString& setTo) override
	{
		_pinBuffer = setTo;
	}
	virtual tscrypto::tsCryptoString URL() override
	{
		return _url;
	}
	virtual void URL(const tscrypto::tsCryptoString& setTo) override
	{
		_url = setTo;
	}
	virtual tscrypto::tsCryptoString UserName() override
	{
		return _username;
	}
	virtual void UserName(const tscrypto::tsCryptoString& setTo) override
	{
		_username = setTo;
	}

protected:
	XP_WINDOW							_parent;
	std::shared_ptr<KeyVEILLogIn> Me; // Keep me alive until Destroy is called
	std::shared_ptr<IKeyVEILConnector>	_connector;
	tscrypto::tsCryptoString								_url;
	tscrypto::tsCryptoString								_username;
	tscrypto::tsCryptoString								_pinBuffer;

	/// Creation
	bool Create(wxWindow* parent, wxWindowID id = SYMBOL_KEYVEILLOGIN_IDNAME, const wxString& caption = SYMBOL_KEYVEILLOGIN_TITLE, const wxPoint& pos = SYMBOL_KEYVEILLOGIN_POSITION, const wxSize& size = SYMBOL_KEYVEILLOGIN_SIZE, long style = SYMBOL_KEYVEILLOGIN_STYLE)
	{
		Me = std::dynamic_pointer_cast<KeyVEILLogIn>(_me.lock());
		////@begin KeyVEILLogin creation
		SetExtraStyle(wxWS_EX_VALIDATE_RECURSIVELY | wxWS_EX_BLOCK_EVENTS);
		wxDialog::Create(parent, id, caption, pos, size, style);

		CreateControls();
		if (GetSizer())
		{
			GetSizer()->SetSizeHints(this);
		}
		Centre();
		////@end KeyVEILLogin creation

		OnInitDialog();
		return true;
	}
	/// Initialises member variables
	void Init()
	{
		////@begin KeyVEILLogin member initialisation
		edtURL = NULL;
		edtUsername = NULL;
		edtPassword = NULL;
		edtStatus = NULL;
		////@end KeyVEILLogin member initialisation

	}

	/// Creates the controls and sizers
	void CreateControls()
	{
		////@begin KeyVEILLogin content construction
		KeyVEILLogIn* itemDialog1 = this;

		wxFlexGridSizer* itemFlexGridSizer2 = new wxFlexGridSizer(6, 1, 0, 0);
		itemDialog1->SetSizer(itemFlexGridSizer2);

		wxStaticBitmap* itemStaticBitmap3 = new wxStaticBitmap(itemDialog1, wxID_STATIC, itemDialog1->GetBitmapResource(wxT("../../src/tecseclogo.xpm")), wxDefaultPosition, wxSize(372, 73), 0);
		itemFlexGridSizer2->Add(itemStaticBitmap3, 0, wxALIGN_CENTER_HORIZONTAL | wxALIGN_CENTER_VERTICAL | wxALL, 0);

		wxFlexGridSizer* itemFlexGridSizer4 = new wxFlexGridSizer(0, 2, 0, 0);
		itemFlexGridSizer2->Add(itemFlexGridSizer4, 0, wxGROW | wxALIGN_CENTER_VERTICAL | wxALL, 5);

		wxStaticText* itemStaticText5 = new wxStaticText(itemDialog1, wxID_STATIC, _("KeyVEIL URL:"), wxDefaultPosition, wxDefaultSize, 0);
		itemFlexGridSizer4->Add(itemStaticText5, 0, wxALIGN_LEFT | wxALIGN_CENTER_VERTICAL | wxALL, 5);

		edtURL = new wxTextCtrl(itemDialog1, ID_URL, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0);
		itemFlexGridSizer4->Add(edtURL, 0, wxGROW | wxALIGN_CENTER_VERTICAL | wxALL, 0);

		wxStaticText* itemStaticText7 = new wxStaticText(itemDialog1, wxID_STATIC, _("Username:"), wxDefaultPosition, wxDefaultSize, 0);
		itemFlexGridSizer4->Add(itemStaticText7, 0, wxALIGN_LEFT | wxALIGN_CENTER_VERTICAL | wxALL, 5);

		edtUsername = new wxTextCtrl(itemDialog1, ID_USERNAME, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0);
		itemFlexGridSizer4->Add(edtUsername, 0, wxGROW | wxALIGN_CENTER_VERTICAL | wxALL, 0);

		itemFlexGridSizer4->AddGrowableCol(1);

		wxStaticText* itemStaticText9 = new wxStaticText(itemDialog1, wxID_STATIC, _("Please enter the user password here:"), wxDefaultPosition, wxDefaultSize, 0);
		itemFlexGridSizer2->Add(itemStaticText9, 0, wxALIGN_LEFT | wxALIGN_CENTER_VERTICAL | wxALL, 5);

		edtPassword = new wxTextCtrl(itemDialog1, ID_PASSWORD, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_PASSWORD);
		edtPassword->SetMaxLength(64);
		itemFlexGridSizer2->Add(edtPassword, 0, wxGROW | wxALIGN_CENTER_VERTICAL | wxALL, 5);

		edtStatus = new wxStaticText(itemDialog1, ID_STATUS, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0);
		edtStatus->Wrap(360);
		itemFlexGridSizer2->Add(edtStatus, 0, wxGROW | wxALIGN_CENTER_VERTICAL | wxALL, 5);

		wxStdDialogButtonSizer* itemStdDialogButtonSizer12 = new wxStdDialogButtonSizer;

		itemFlexGridSizer2->Add(itemStdDialogButtonSizer12, 0, wxALIGN_CENTER_HORIZONTAL | wxALIGN_CENTER_VERTICAL | wxALL, 5);
		wxButton* itemButton13 = new wxButton(itemDialog1, wxID_CANCEL, _("&Cancel"), wxDefaultPosition, wxDefaultSize, 0);
		itemStdDialogButtonSizer12->AddButton(itemButton13);

		wxButton* itemButton14 = new wxButton(itemDialog1, wxID_HELP, _("&Help"), wxDefaultPosition, wxDefaultSize, 0);
		itemStdDialogButtonSizer12->AddButton(itemButton14);

		wxButton* itemButton15 = new wxButton(itemDialog1, wxID_OK, _("&OK"), wxDefaultPosition, wxDefaultSize, 0);
		itemButton15->SetDefault();
		itemStdDialogButtonSizer12->AddButton(itemButton15);

		wxButton* itemButton16 = new wxButton(itemDialog1, wxID_APPLY, _("&About"), wxDefaultPosition, wxDefaultSize, 0);
		itemStdDialogButtonSizer12->AddButton(itemButton16);

		itemStdDialogButtonSizer12->Realize();

		itemFlexGridSizer2->AddGrowableRow(5);

		////@end KeyVEILLogin content construction
	}

	/// wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_HELP
	void OnHelpClick(wxCommandEvent& event)
	{
		////@begin wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_HELP in KeyVEILLogin.
			// Before editing this code, remove the block markers.
		event.Skip();
		////@end wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_HELP in KeyVEILLogin. 
	}

	/// wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_OK
	void OnOkClick(wxCommandEvent& event)
	{
		_url = edtURL->GetValue().mbc_str();
		_username = edtUsername->GetValue().mbc_str();
		_pinBuffer = edtPassword->GetValue().mbc_str();

		event.StopPropagation();

		if ((int)TsStrLen(_pinBuffer) < KEYVEIL_MIN_PIN_LEN)
		{
			char buff[MAX_PATH + 1];

#ifdef HAVE_SPRINTF_S
			sprintf_s(buff, sizeof(buff), "The minimum password length is %d.", KEYVEIL_MIN_PIN_LEN);
#else
			sprintf(buff, "The minimum password length is %d.", KEYVEIL_MIN_PIN_LEN);
#endif
			wxMessageBox(buff, "Error", MB_OK);
		}
		else
		{
			_pinBuffer.resize(TsStrLen(_pinBuffer));
			switch (_connector->connect(_url, _username, _pinBuffer))
			{
			case ConnectionStatus::connStatus_BadAuth:
				edtStatus->SetLabelText(_("The username or password was invalid."));
				break;
			case ConnectionStatus::connStatus_Connected:
				EndDialog(wxID_OK);
				break;
			case ConnectionStatus::connStatus_NoServer:
			{
				char buff[MAX_PATH + 1];

				TsStrCpy(buff, sizeof(buff), "The communications to the server was lost.");
				wxMessageBox(buff, "Error", MB_OK);

				edtStatus->SetLabelText(buff);
			}
			break;
			case ConnectionStatus::connStatus_UrlBad:
			{
				char buff[MAX_PATH + 1];

				TsStrCpy(buff, sizeof(buff), "The specified URL is invalid.");
				wxMessageBox(buff, "Error", MB_OK);
				edtStatus->SetLabelText(buff);
			}
			break;
			case ConnectionStatus::connStatus_WrongProtocol:
			{
				char buff[MAX_PATH + 1];

				TsStrCpy(buff, sizeof(buff), "The protocol specifier on the URL was not recognized.");
				wxMessageBox(buff, "Error", MB_OK);
				edtStatus->SetLabelText(buff);
			}
			break;
			}
		}
	}

	/// wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_APPLY
	void OnApplyClick(wxCommandEvent& event)
	{
		std::shared_ptr<IVEILWxUIBase> dlg = ::TopServiceLocator()->get_instance<IVEILWxUIBase>("/WxWin/AboutCkm");

		dlg->DisplayModal((XP_WINDOW)this);
	}

	/// Should we show tooltips?
	static bool ShowToolTips()
	{
		return true;
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

	int GetPinRetryCount(std::shared_ptr<IKeyVEILSession> session)
	{
		return (int)session->retriesLeft();
	}

	void OnInitDialog()
	{
		std::shared_ptr<BasicVEILPreferences> prefs = BasicVEILPreferences::Create();

		prefs->loadValues();

		if (_url.size() == 0)
		{
			_url = prefs->getKeyVEILUrl();
		}
		if (_username.size() == 0)
		{
			_username = prefs->getKeyVEILUsername();
		}

		if (_connector->isConnected())
		{
			EndDialog(wxID_OK);
		}
		else
		{
			edtURL->SetValue(_url.c_str());
			edtUsername->SetValue(_username.c_str());
		}
		if (_url.size() > 0)
		{
			if (_username.size() > 0)
			{
				edtPassword->SetFocus();
			}
			else
			{
				edtUsername->SetFocus();
			}
		}
	}

private:
	////@begin KeyVEILLogin member variables
	wxTextCtrl* edtURL;
	wxTextCtrl* edtUsername;
	wxTextCtrl* edtPassword;
	wxStaticText* edtStatus;
	////@end KeyVEILLogin member variables
};

/*
* KeyVEILLogIn event table definition
*/

BEGIN_EVENT_TABLE(KeyVEILLogIn, wxDialog)

////@begin KeyVEILLogin event table entries
EVT_BUTTON(wxID_HELP, KeyVEILLogIn::OnHelpClick)
EVT_BUTTON(wxID_OK, KeyVEILLogIn::OnOkClick)
EVT_BUTTON(wxID_APPLY, KeyVEILLogIn::OnApplyClick)
////@end KeyVEILLogin event table entries

END_EVENT_TABLE()

tsmod::IObject* CreateKeyVEILLogIn()
{
	return dynamic_cast<tsmod::IObject*>(new KeyVEILLogIn());
}