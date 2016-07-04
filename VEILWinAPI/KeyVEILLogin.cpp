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
#include "resource.h"

#define KEYVEIL_MIN_PIN_LEN 6
#define KEYVEIL_MAX_PIN_LEN 64

class KeyVEILLogIn : public IKeyVEILLogin, public tsmod::IObject
{
public:
	KeyVEILLogIn() : _parent(nullptr)
	{}
	virtual ~KeyVEILLogIn(){}

	// IVEILUIBase
	virtual void Destroy()
	{
		_parent = XP_WINDOW_INVALID;
		_connector.reset();
		_url.clear();
		_username.clear();
		_pinBuffer.clear();
	}
	virtual int  DisplayModal()
	{
		if (_parent == XP_WINDOW_INVALID)
			_parent = (XP_WINDOW)GetActiveWindow();
		return (int)DialogBoxParamA((HINSTANCE)hDllInstance, MAKEINTRESOURCEA(IDD_KEYVEILLOGIN), (HWND)_parent, LoginProc, (LPARAM)this);
	}
	virtual int  DisplayModal(XP_WINDOW wnd)
	{
		_parent = wnd;
		return DisplayModal();
	}

	// IKeyVEILLogIn
	virtual bool Start(std::shared_ptr<IKeyVEILConnector> connector, XP_WINDOW parent)
	{
		Destroy();

		_connector = connector;
		_parent = parent;

		if (!_connector)
		{
			_connector = ::TopServiceLocator()->try_get_instance<IKeyVEILConnector>("KeyVEILConnector");
		}
		if (!_connector)
		{
			MessageBox((HWND)parent, "An error occurred while creating the KeyVEIL Connector.", "ERROR", MB_OK);
			return false;
		}

		return true;
	}
	virtual std::shared_ptr<IKeyVEILConnector> Connector()
	{
		return _connector;
	}
	virtual tscrypto::tsCryptoString Pin()
	{
		return _pinBuffer;
	}
	virtual void Pin(const tscrypto::tsCryptoString& setTo)
	{
		_pinBuffer = setTo;
	}
	virtual tscrypto::tsCryptoString URL()
	{
		return _url;
	}
	virtual void URL(const tscrypto::tsCryptoString& setTo)
	{
		_url = setTo;
	}
	virtual tscrypto::tsCryptoString UserName()
	{
		return _username;
	}
	virtual void UserName(const tscrypto::tsCryptoString& setTo)
	{
		_username = setTo;
	}

protected:
	XP_WINDOW							_parent;
	std::shared_ptr<IKeyVEILConnector>	_connector;
	tscrypto::tsCryptoString								_url;
	tscrypto::tsCryptoString								_username;
	tscrypto::tsCryptoString								_pinBuffer;

	int GetPinRetryCount(std::shared_ptr<IKeyVEILSession> session)
	{
		return (int)session->retriesLeft();
	}

	void OnInitDialog(HWND hDlg)
	{
		tscrypto::tsCryptoString buff;
		tscrypto::tsCryptoString path;
		JSONObject settings;

		// Get the application default values for the URL and Username
		xp_GetSpecialFolder(sft_UserConfigFolder, path);

		std::shared_ptr<IDataReader> reader = std::dynamic_pointer_cast<IDataReader>(CreateFileReader(path + "default.ovc"));

		if (reader->DataLength() > 0)
		{
			tscrypto::tsCryptoData data;

			if (reader->ReadData((int)reader->DataLength(), data))
				settings.FromJSON(data.ToUtf8String().c_str());
		}
		reader->Close();
		reader.reset();

		if (_url.size() == 0)
		{
			_url = settings.AsString("KeyVEILUrl");
		}
		if (_username.size() == 0)
		{
			_username = settings.AsString("KeyVEILUsername");
		}

		if (logo > (HBITMAP)1)
		{
			SendDlgItemMessageA(hDlg, IDC_TECSEC_LOGO, STM_SETIMAGE, IMAGE_BITMAP, LPARAM(logo));
		}
		SendDlgItemMessage(hDlg, IDC_PASSWORD, EM_SETLIMITTEXT, KEYVEIL_MAX_PIN_LEN, 0);

		if (_connector->isConnected())
		{
			EndDialog(hDlg, IDOK);
		}
		else
		{
			SetDlgItemText(hDlg, IDC_URL, _url.c_str());
			SetDlgItemText(hDlg, IDC_USERNAME, _username.c_str());
		}
		if (_url.size() == 0)
		{
			SetFocus(GetDlgItem(hDlg, IDC_URL));
		}
		else if (_username.size() == 0)
		{
			SetFocus(GetDlgItem(hDlg, IDC_USERNAME));
		}
		else
		{
			SetFocus(GetDlgItem(hDlg, IDC_PASSWORD));
		}

		{
			HWINSTA station = GetProcessWindowStation();
			DWORD count;

			buff.clear();
			buff.resize(512);
			GetUserObjectInformation(station, UOI_NAME, buff.rawData(), (DWORD)buff.size(), &count);
			if (TsStrStr(buff, ("WinSta0")) == NULL)
			{
				EndDialog(hDlg, IDCANCEL);
			}
		}
	}

	void OnAbout(HWND hDlg)
	{
		std::shared_ptr<IVEILUIBase> about = ::TopServiceLocator()->try_get_instance<IVEILUIBase>("/WinAPI/AboutCkm");

		if (!!about)
			about->DisplayModal((XP_WINDOW)hDlg);
	}
	INT_PTR OnOK(HWND hDlg)
	{
		{
			char buff[512];

			buff[0] = 0;
			GetDlgItemText(hDlg, IDC_URL, buff, sizeof(buff));
			_url = buff;

			buff[0] = 0;
			GetDlgItemText(hDlg, IDC_USERNAME, buff, sizeof(buff));
			_username = buff;
		}
		_pinBuffer.clear();
		_pinBuffer.resize(100);
		GetDlgItemTextA(hDlg, IDC_PASSWORD, _pinBuffer.rawData(), (int)_pinBuffer.size());
		if ((int)TsStrLen(_pinBuffer) < KEYVEIL_MIN_PIN_LEN)
		{
			char buff[MAX_PATH + 1];

#ifdef HAVE_SPRINTF_S
			sprintf_s(buff, sizeof(buff), "The minimum password length is %d.", KEYVEIL_MIN_PIN_LEN);
#else
			sprintf(buff, "The minimum password length is %d.", KEYVEIL_MIN_PIN_LEN);
#endif
			MessageBoxA(hDlg, buff, "Error", MB_OK);
		}
		else
		{
			_pinBuffer.resize(TsStrLen(_pinBuffer));
			switch (_connector->connect(_url, _username, _pinBuffer))
			{
			case ConnectionStatus::connStatus_BadAuth:
				SetDlgItemTextA(hDlg, IDC_STATUS, "The username or password was invalid.");
				break;
			case ConnectionStatus::connStatus_Connected:
				EndDialog(hDlg, IDOK);
				break;
			case ConnectionStatus::connStatus_NoServer:
			{
				char buff[MAX_PATH + 1];

				TsStrCpy(buff, sizeof(buff), "The communications to the server was lost.");
				MessageBoxA(hDlg, buff, "Error", MB_OK);
				SetDlgItemTextA(hDlg, IDC_STATUS, buff);
			}
			break;
			case ConnectionStatus::connStatus_UrlBad:
			{
				char buff[MAX_PATH + 1];

				TsStrCpy(buff, sizeof(buff), "The specified URL is invalid.");
				MessageBoxA(hDlg, buff, "Error", MB_OK);
				SetDlgItemTextA(hDlg, IDC_STATUS, buff);
			}
			break;
			case ConnectionStatus::connStatus_WrongProtocol:
			{
				char buff[MAX_PATH + 1];

				TsStrCpy(buff, sizeof(buff), "The protocol specifier on the URL was not recognized.");
				MessageBoxA(hDlg, buff, "Error", MB_OK);
				SetDlgItemTextA(hDlg, IDC_STATUS, buff);
			}
			break;
			}
		}
		return (INT_PTR)TRUE;
	}

	static INT_PTR CALLBACK	LoginProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
	{
		KeyVEILLogIn *params = (KeyVEILLogIn*)GetWindowLongPtr(hWnd, DWLP_USER);

		switch (msg)
		{
		case WM_INITDIALOG:
		{
			tscrypto::tsCryptoString buff;
			params = (KeyVEILLogIn*)lParam;

			SetWindowLongPtr(hWnd, DWLP_USER, lParam);

			params->OnInitDialog(hWnd);

			return (INT_PTR)FALSE;
		}
		case WM_COMMAND:
			if (LOWORD(wParam) == IDC_ABOUT)
			{
				params->OnAbout(hWnd);
			}
			else if (LOWORD(wParam) == IDOK)
			{
				return params->OnOK(hWnd);
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

tsmod::IObject* CreateKeyVEILLogIn()
{
	return dynamic_cast<tsmod::IObject*>(new KeyVEILLogIn());
}