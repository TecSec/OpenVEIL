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
#include "resource.h"

class TokenLogIn : public ITokenLogin, public tsmod::IObject
{
public:
	TokenLogIn() : _parent(nullptr), _minLen(6), _maxLen(64), _result(0)
	{}
	virtual ~TokenLogIn(){}

	// IVEILUIBase
	virtual void Destroy()
	{
		_parent = XP_WINDOW_INVALID;
		_session.reset();
		_minLen = 6;
		_maxLen = 64;
		_result = 0;
		_pinBuffer.clear();
	}
	virtual int  DisplayModal()
	{
		if (_parent == XP_WINDOW_INVALID)
			_parent = (XP_WINDOW)GetActiveWindow();
		return (int)DialogBoxParamA((HINSTANCE)hDllInstance, MAKEINTRESOURCEA(IDD_LOGIN), (HWND)_parent, LoginProc, (LPARAM)this);
	}
	virtual int  DisplayModal(XP_WINDOW wnd)
	{
		_parent = wnd;
		return DisplayModal();
	}

	// IAudienceSelector
	virtual bool Start(std::shared_ptr<IKeyVEILSession> session, XP_WINDOW parent)
	{
		if (!session)
		{
			LOG(FrameworkError, "TokenLogin called without a session");
			return false;
		}
		if (!session->GetProfile())
		{
			LOG(FrameworkError, "TokenLogin called with a session that could not get the profile.");
			return false;
		}


		Asn1::CTS::_POD_PasswordPolicy policy = session->GetProfile()->get_passwordPolicy();

		_session = session;
		_minLen = policy.get_minLength();
		_maxLen = policy.get_maxLength();

		//if (SUCCEEDED(session->QueryInterface(__uuidof(ICKMSessionSSO), (void**)&sso)))
		//	params.sso = sso;

		return true;
	}
	virtual tscrypto::tsCryptoString Pin()
	{
		return _pinBuffer;
	}
	virtual void Pin(const tscrypto::tsCryptoString& setTo)
	{
		_pinBuffer = setTo;
	}
protected:
	XP_WINDOW						 _parent;
	std::shared_ptr<IKeyVEILSession> _session;
	//ICKMSessionSSO *sso;
	int								 _minLen;
	int								 _maxLen;
	int								 _result;
	tscrypto::tsCryptoString							 _pinBuffer;

	int GetPinRetryCount(std::shared_ptr<IKeyVEILSession> session)
	{
		return (int)session->retriesLeft();
	}

	static INT_PTR CALLBACK	LoginProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
	{
		TokenLogIn *params = (TokenLogIn*)GetWindowLongPtr(hWnd, DWLP_USER);

		switch (msg)
		{
		case WM_INITDIALOG:
		{
			tscrypto::tsCryptoString buff;
			params = (TokenLogIn*)lParam;

			SetWindowLongPtr(hWnd, DWLP_USER, lParam);

			if (logo > (HBITMAP)1)
			{
				SendDlgItemMessageA(hWnd, IDC_TECSEC_LOGO, STM_SETIMAGE, IMAGE_BITMAP, LPARAM(logo));
			}
			SendDlgItemMessage(hWnd, IDC_PASSWORD, EM_SETLIMITTEXT, params->_maxLen, 0);
			
			if (params->_session->GetProfile()->exists_tokenName())
				buff = *params->_session->GetProfile()->get_tokenName();
			if (buff.size() > 0)
			{
				SetDlgItemTextA(hWnd, IDC_TOKEN_NAME, buff.c_str());
			}
			else
				SetDlgItemTextA(hWnd, IDC_TOKEN_NAME, "unknown token");

			params->_result = E_FAIL;
			if (params->_session->IsLoggedIn())
			{
				params->_result = S_OK;
				EndDialog(hWnd, IDOK);
			}
			else
			{
				switch (params->GetPinRetryCount(params->_session))
				{
				case 0:
					if (params->_session->LastKeyVEILStatus() == 401 || params->_session->LastKeyVEILStatus() == 440)
					{
						MessageBoxA(hWnd, "The KeyVEIL connector is no longer authenticated.", "Error", MB_OK);
						params->_result = ERROR_NOT_AUTHENTICATED;
					}
					else
					{
						MessageBoxA(hWnd, "The token is locked.", "Error", MB_OK);
						params->_result = ERROR_ACCOUNT_LOCKED_OUT;
					}
					EndDialog(hWnd, IDOK);
					break;
				case 1:
					SetDlgItemTextA(hWnd, IDC_STATUS, "This token has one try left.");
					break;
				case 2:
					SetDlgItemTextA(hWnd, IDC_STATUS, "At least one login attempt has failed.");
					break;
				}
				//
				// Now we need to check for the authenticated path
				//
				//if (params->_session->UsesAuthenticatedPath())
				//{
				//	params->_result = params->_session->Login("TecSec");
				//	if (params->_result == 0)
				//		EndDialog(hWnd, IDOK);
				//	else
				//	{
				//		MessageBoxA(hWnd, "The password for this token does not match the stored password.  Please enter the token password.", "Error", MB_OK);
				//	}
				//}
				//else
				//{
				//	HRESULT hr;
				//	//
				//	// Now we need to check for SSO systems.
				//	//
				//	if (params->sso != NULL)
				//	{
				//		if ((hr = params->sso->SSOLogin()) == S_OK || SUCCEEDED(hr))
				//		{
				//			if (hr == XP_HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED))
				//			{
				//				MessageBoxA(hWnd, "The Single Sign-on provider supplied an incorrect password for this Token.", "Error", MB_OK | MB_ICONWARNING);
				//			}
				//			params->result = hr;
				//			EndDialog(hWnd, IDOK);
				//		}
				//	}
				//}
			}
			{
				HWINSTA station = GetProcessWindowStation();
				DWORD count;

				buff.clear();
				buff.resize(512);
				GetUserObjectInformation(station, UOI_NAME, buff.rawData(), (DWORD)buff.size(), &count);
				if (TsStrStr(buff.c_str(), ("WinSta0")) == NULL)
				{
					params->_result = E_FAIL;
					EndDialog(hWnd, IDCANCEL);
				}
			}

			return (INT_PTR)TRUE;
		}
		case WM_COMMAND:
			if (LOWORD(wParam) == IDC_ABOUT)
			{
				std::shared_ptr<IVEILUIBase> about = ::TopServiceLocator()->try_get_instance<IVEILUIBase>("/WinAPI/AboutCkm");

				if (!!about)
					about->DisplayModal((XP_WINDOW)hWnd);
			}
			else if (LOWORD(wParam) == IDOK)
			{
				if (params != NULL)
				{
					params->_pinBuffer.clear();
					params->_pinBuffer.resize(100);
					GetDlgItemTextA(hWnd, IDC_PASSWORD, params->_pinBuffer.rawData(), (int)params->_pinBuffer.size());
					if ((int)TsStrLen(params->_pinBuffer.c_str()) < params->_minLen)
					{
						char buff[MAX_PATH + 1];

#ifdef HAVE_SPRINTF_S
						sprintf_s(buff, sizeof(buff), "The minimum password length is %d.", params->_minLen);
#else
						sprintf(buff, "The minimum password length is %d.", params->_minLen);
#endif
						MessageBoxA(hWnd, buff, "Error", MB_OK);
					}
					else
					{
						params->_pinBuffer.resize(TsStrLen(params->_pinBuffer.c_str()));
						params->_result = params->_session->Login(params->_pinBuffer);
						switch ((LoginStatus)params->_result)
						{
						case LoginStatus::loginStatus_BadAuth:
							if (params->_session->retriesLeft() == 0)
							{
								MessageBoxA(hWnd, "The token is locked.", "Error", MB_OK);
								params->_result = ERROR_ACCOUNT_LOCKED_OUT;
								EndDialog(hWnd, IDOK);
							}
							else if (params->_session->retriesLeft() == 1)
							{
								SetDlgItemTextA(hWnd, IDC_STATUS, "This token has one try left.");
							}
							else
							{
								SetDlgItemTextA(hWnd, IDC_STATUS, "The login count is low.");
							}
							break;
						case LoginStatus::loginStatus_Connected:
							//
							// Establish the pin in any SSO system that is currently active
							//
							//if (params->sso != NULL)
							//{
							//	if (MessageBoxA(hWnd, "Would you like to have the system remember this token password?", "Single Sign On", MB_YESNO | MB_ICONQUESTION) == IDYES)
							//		params->sso->SSOSetPin(params->_pinBuffer);
							//	else
							//		params->sso->SSOSetPin("");
							//}
							EndDialog(hWnd, LOWORD(wParam));
							break;
						case LoginStatus::loginStatus_NoServer:
						{
							char buff[MAX_PATH + 1];

							TsStrCpy(buff, sizeof(buff), "The communications to the server was lost.");
							MessageBoxA(hWnd, buff, "Error", MB_OK);
							SetDlgItemTextA(hWnd, IDC_STATUS, buff);
						}
							break;
						}
					}
					return (INT_PTR)TRUE;
				}
				return (INT_PTR)FALSE;
			}
			if (LOWORD(wParam) == IDCANCEL)
			{
				EndDialog(hWnd, LOWORD(wParam));
				return (INT_PTR)TRUE;
			}
			break;
		}
		return (INT_PTR)FALSE;
	}
};

tsmod::IObject* CreateTokenLogIn()
{
	return dynamic_cast<tsmod::IObject*>(new TokenLogIn());
}