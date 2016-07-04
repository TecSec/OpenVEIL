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

/*!
 * Control identifiers
 */

 ////@begin control identifiers
#define ID_TOKENLOGIN 10000
#define ID_TOKENNAME 10010
#define ID_TEXTCTRL 10001
#define ID_STATUS 10011
#define SYMBOL_TOKENLOGIN_STYLE wxCAPTION|wxSYSTEM_MENU|wxCLOSE_BOX|wxTAB_TRAVERSAL
#define SYMBOL_TOKENLOGIN_TITLE _("Token Login")
#define SYMBOL_TOKENLOGIN_IDNAME ID_TOKENLOGIN
#define SYMBOL_TOKENLOGIN_SIZE wxSize(400, 300)
#define SYMBOL_TOKENLOGIN_POSITION wxDefaultPosition
////@end control identifiers

class TokenLogin : public ITokenLogin, public tsmod::IObject, public wxDialog
{
	DECLARE_EVENT_TABLE()

public:
	TokenLogin() : _parent(nullptr), _minLen(6), _maxLen(64), _result(0)
	{}
	virtual ~TokenLogin() {}

	// wxDialog
	virtual bool Destroy() override
	{
		_parent = XP_WINDOW_INVALID;
		_session.reset();
		_minLen = 6;
		_maxLen = 64;
		_result = 0;
		_pinBuffer.clear();
		Me.reset();
		return true;
	}
	// IVEILWxUIBase
	virtual int  DisplayModal() override
	{
		if (_parent == XP_WINDOW_INVALID)
			_parent = (XP_WINDOW)wxTheApp->GetTopWindow();

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

	// ITokenLogin
	virtual bool Start(std::shared_ptr<IKeyVEILSession> session, XP_WINDOW parent) override
	{
		if (!session || !session->GetProfile())
			return false;

		Asn1::CTS::PasswordPolicy policy = session->GetProfile()->get_passwordPolicy();

		_session = session;
		_minLen = policy.get_minLength();
		_maxLen = policy.get_maxLength();

		//if (SUCCEEDED(session->QueryInterface(__uuidof(ICKMSessionSSO), (void**)&sso)))
		//	params.sso = sso;

		return true;
	}
	virtual tscrypto::tsCryptoString Pin() override
	{
		return _pinBuffer;
	}
	virtual void Pin(const tscrypto::tsCryptoString& setTo) override
	{
		_pinBuffer = setTo;
	}
protected:
	XP_WINDOW						 _parent;
	std::shared_ptr<TokenLogin> Me; // Keep me alive until Destroy is called
	std::shared_ptr<IKeyVEILSession> _session;
	//ICKMSessionSSO *sso;
	int								 _minLen;
	int								 _maxLen;
	int								 _result;
	tscrypto::tsCryptoString							 _pinBuffer;

	/// Creation
	bool Create(wxWindow* parent, wxWindowID id = SYMBOL_TOKENLOGIN_IDNAME, const wxString& caption = SYMBOL_TOKENLOGIN_TITLE, const wxPoint& pos = SYMBOL_TOKENLOGIN_POSITION, const wxSize& size = SYMBOL_TOKENLOGIN_SIZE, long style = SYMBOL_TOKENLOGIN_STYLE)
	{
		Me = std::dynamic_pointer_cast<TokenLogin>(_me.lock());

		////@begin TokenLogin creation
		SetExtraStyle(wxWS_EX_VALIDATE_RECURSIVELY | wxWS_EX_BLOCK_EVENTS);
		wxDialog::Create(parent, id, caption, pos, size, style);

		CreateControls();
		if (GetSizer())
		{
			GetSizer()->SetSizeHints(this);
		}
		Centre();

		OnInitDialog();

		////@end TokenLogin creation
		return true;
	}
	/// Initialises member variables
	void Init()
	{
		////@begin TokenLogin member initialisation
		lblTokenName = NULL;
		edtPassword = NULL;
		lblStatus = NULL;
		btnOK = NULL;
		btnCancel = NULL;
		btnAbout = NULL;
		////@end TokenLogin member initialisation
	}
	/// Creates the controls and sizers
	void CreateControls()
	{
		////@begin TokenLogin content construction
		TokenLogin* itemDialog1 = this;

		wxFlexGridSizer* itemFlexGridSizer2 = new wxFlexGridSizer(0, 1, 0, 0);
		itemDialog1->SetSizer(itemFlexGridSizer2);

		wxStaticBitmap* itemStaticBitmap3 = new wxStaticBitmap(itemDialog1, wxID_STATIC, itemDialog1->GetBitmapResource(wxT("../../src/tecseclogo.xpm")), wxDefaultPosition, wxSize(372, 73), 0);
		itemFlexGridSizer2->Add(itemStaticBitmap3, 0, wxALIGN_CENTER_HORIZONTAL | wxALIGN_CENTER_VERTICAL | wxALL, 0);

		wxFlexGridSizer* itemFlexGridSizer4 = new wxFlexGridSizer(0, 2, 0, 0);
		itemFlexGridSizer2->Add(itemFlexGridSizer4, 0, wxGROW | wxALIGN_CENTER_VERTICAL | wxALL, 5);

		wxStaticText* itemStaticText5 = new wxStaticText(itemDialog1, wxID_STATIC, _("Token Name:"), wxDefaultPosition, wxDefaultSize, 0);
		itemFlexGridSizer4->Add(itemStaticText5, 0, wxALIGN_CENTER_HORIZONTAL | wxALIGN_CENTER_VERTICAL | wxALL, 5);

		lblTokenName = new wxStaticText(itemDialog1, ID_TOKENNAME, _("Static text"), wxDefaultPosition, wxDefaultSize, 0);
		lblTokenName->Wrap(300);
		itemFlexGridSizer4->Add(lblTokenName, 0, wxALIGN_CENTER_HORIZONTAL | wxALIGN_CENTER_VERTICAL | wxALL, 5);

		itemFlexGridSizer2->Add(5, 5, 0, wxALIGN_CENTER_HORIZONTAL | wxALIGN_CENTER_VERTICAL | wxALL, 5);

		wxStaticText* itemStaticText8 = new wxStaticText(itemDialog1, wxID_STATIC, _("Please enter the token password here:"), wxDefaultPosition, wxDefaultSize, 0);
		itemFlexGridSizer2->Add(itemStaticText8, 0, wxALIGN_LEFT | wxALIGN_CENTER_VERTICAL | wxALL, 5);

		edtPassword = new wxTextCtrl(itemDialog1, ID_TEXTCTRL, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_PASSWORD);
		itemFlexGridSizer2->Add(edtPassword, 0, wxGROW | wxALIGN_CENTER_VERTICAL | wxALL, 5);

		lblStatus = new wxStaticText(itemDialog1, ID_STATUS, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0);
		lblStatus->Wrap(360);
		itemFlexGridSizer2->Add(lblStatus, 0, wxALIGN_LEFT | wxALIGN_CENTER_VERTICAL | wxALL, 5);

		wxStdDialogButtonSizer* itemStdDialogButtonSizer11 = new wxStdDialogButtonSizer;

		itemFlexGridSizer2->Add(itemStdDialogButtonSizer11, 0, wxALIGN_CENTER_HORIZONTAL | wxALIGN_CENTER_VERTICAL | wxALL, 5);
		btnOK = new wxButton(itemDialog1, wxID_OK, _("&OK"), wxDefaultPosition, wxDefaultSize, 0);
	    btnOK->SetDefault();
		itemStdDialogButtonSizer11->AddButton(btnOK);

		btnCancel = new wxButton(itemDialog1, wxID_CANCEL, _("&Cancel"), wxDefaultPosition, wxDefaultSize, 0);
		itemStdDialogButtonSizer11->AddButton(btnCancel);

		btnAbout = new wxButton(itemDialog1, wxID_APPLY, _("&About"), wxDefaultPosition, wxDefaultSize, 0);
		itemStdDialogButtonSizer11->AddButton(btnAbout);

		itemStdDialogButtonSizer11->Realize();

		////@end TokenLogin content construction
	}

	////@begin TokenLogin event handler declarations

		/// wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_OK
	void OnOkClick(wxCommandEvent& event)
	{
		event.StopPropagation();

		_pinBuffer = edtPassword->GetValue().mbc_str();
		if ((int)TsStrLen(_pinBuffer) < _minLen)
		{
			char buff[MAX_PATH + 1];

#ifdef HAVE_SPRINTF_S
			sprintf_s(buff, sizeof(buff), "The minimum password length is %d.", _minLen);
#else
			sprintf(buff, "The minimum password length is %d.", _minLen);
#endif
			wxMessageBox(buff, "Error", MB_OK);
		}
		else
		{
			_pinBuffer.resize(TsStrLen(_pinBuffer));
			_result = _session->Login(_pinBuffer);
			switch ((LoginStatus)_result)
			{
			case LoginStatus::loginStatus_BadAuth:
				if (_session->retriesLeft() == 0)
				{
					wxMessageBox("The token is locked.", "Error", MB_OK);
					_result = ERROR_ACCOUNT_LOCKED_OUT;
					EndDialog(wxID_OK);
				}
				else if (_session->retriesLeft() == 1)
				{
					lblStatus->SetLabel("This token has one try left.");
				}
				else
				{
					lblStatus->SetLabel("The login count is low.");
				}
				break;
			case LoginStatus::loginStatus_Connected:
				//
				// Establish the pin in any SSO system that is currently active
				//
				//if (sso != NULL)
				//{
				//	if (wxMessageBox(hWnd, "Would you like to have the system remember this token password?", "Single Sign On", MB_YESNO | MB_ICONQUESTION) == wxID_YES)
				//		sso->SSOSetPin(_pinBuffer);
				//	else
				//		sso->SSOSetPin("");
				//}
				EndDialog(wxID_OK);
				break;
			case LoginStatus::loginStatus_NoServer:
			{
				char buff[MAX_PATH + 1];

				TsStrCpy(buff, sizeof(buff), "The communications to the server was lost.");
				wxMessageBox(buff, "Error", MB_OK);
				lblStatus->SetLabel(buff);
			}
			break;
			}
		}
	}

	/// wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_CANCEL
	void OnCancelClick(wxCommandEvent& event)
	{
		event.StopPropagation();
		EndDialog(wxID_CANCEL);
	}

	/// wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_APPLY
	void OnApplyClick(wxCommandEvent& event)
	{
		std::shared_ptr<IVEILWxUIBase> dlg = ::TopServiceLocator()->get_instance<IVEILWxUIBase>("/WxWin/AboutCkm");

		dlg->DisplayModal((XP_WINDOW)this);
	}

	////@end TokenLogin event handler declarations

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
	void OnInitDialog()
	{
		tscrypto::tsCryptoString buff;

		edtPassword->SetMaxLength(_maxLen);

		if (!_session)
		{
			wxMessageBox("You must call Start before displaying this dialog.");
		}

		buff = _session->GetProfile()->get_tokenName();
		if (buff.size() > 0)
		{
			lblTokenName->SetLabel(buff.c_str());
		}
		else
			lblTokenName->SetLabel("unknown token");

		_result = E_FAIL;
		if (_session->IsLoggedIn())
		{
			_result = S_OK;
			EndDialog(wxID_OK);
		}
		else
		{
			switch (GetPinRetryCount(_session))
			{
			case 0:
				if (_session->LastKeyVEILStatus() == 401 || _session->LastKeyVEILStatus() == 440)
				{
					wxMessageBox("The KeyVEIL connector is no longer authenticated.", "Error", MB_OK);
					_result = ERROR_NOT_AUTHENTICATED;
				}
				else
				{
					wxMessageBox("The token is locked.", "Error", MB_OK);
					_result = ERROR_ACCOUNT_LOCKED_OUT;
				}
				EndDialog(wxID_OK);
				break;
			case 1:
				lblStatus->SetLabel("This token has one try left.");
				break;
			case 2:
				lblStatus->SetLabel("At least one login attempt has failed.");
				break;
			}
			//
			// Now we need to check for the authenticated path
			//
			//if (_session->UsesAuthenticatedPath())
			//{
			//	_result = _session->Login("TecSec");
			//	if (_result == 0)
			//		EndDialog(hWnd, wxID_OK);
			//	else
			//	{
			//		wxMessageBox(hWnd, "The password for this token does not match the stored password.  Please enter the token password.", "Error", MB_OK);
			//	}
			//}
			//else
			//{
			//	HRESULT hr;
			//	//
			//	// Now we need to check for SSO systems.
			//	//
			//	if (sso != NULL)
			//	{
			//		if ((hr = sso->SSOLogin()) == S_OK || SUCCEEDED(hr))
			//		{
			//			if (hr == XP_HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED))
			//			{
			//				wxMessageBox(hWnd, "The Single Sign-on provider supplied an incorrect password for this Token.", "Error", MB_OK | MB_ICONWARNING);
			//			}
			//			result = hr;
			//			EndDialog(hWnd, wxID_OK);
			//		}
			//	}
			//}
		}
	}
	int GetPinRetryCount(std::shared_ptr<IKeyVEILSession> session)
	{
		return (int)session->retriesLeft();
	}

private:
	////@begin TokenLogin member variables
	wxStaticText* lblTokenName;
	wxTextCtrl* edtPassword;
	wxStaticText* lblStatus;
	wxButton* btnOK;
	wxButton* btnCancel;
	wxButton* btnAbout;
	////@end TokenLogin member variables

};

/*
* TokenLogin event table definition
*/

BEGIN_EVENT_TABLE(TokenLogin, wxDialog)

////@begin TokenLogin event table entries
EVT_BUTTON(wxID_OK, TokenLogin::OnOkClick)
EVT_BUTTON(wxID_CANCEL, TokenLogin::OnCancelClick)
EVT_BUTTON(wxID_APPLY, TokenLogin::OnApplyClick)
////@end TokenLogin event table entries

END_EVENT_TABLE()
tsmod::IObject* CreateTokenLogIn()
{
	return dynamic_cast<tsmod::IObject*>(new TokenLogin());
}