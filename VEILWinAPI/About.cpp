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
#include "commctrl.h"

class AboutCkm : public IVEILUIBase, public tsmod::IObject
{
public:
	AboutCkm() : _parent(nullptr)
	{}
	virtual ~AboutCkm(){}

	// IVEILUIBase
	virtual void Destroy()
	{
		_parent = XP_WINDOW_INVALID;
	}
	virtual int  DisplayModal()
	{
		if (_parent == XP_WINDOW_INVALID)
			_parent = (XP_WINDOW)GetActiveWindow();
		return (int)DialogBoxParamA((HINSTANCE)hDllInstance, MAKEINTRESOURCEA(IDD_ABOUT_CKM), (HWND)_parent, AboutCkmProc, (LPARAM)this);
	}
	virtual int  DisplayModal(XP_WINDOW wnd)
	{
		_parent = wnd;
		return DisplayModal();
	}

protected:
	XP_WINDOW		_parent;

	static void GetModuleVersion(HINSTANCE handle, char *versionString, int versionStringLen)
	{
		char path[MAX_PATH + 10];
		DWORD tmp = 0;
		DWORD length;
		unsigned char bytes[1024];
		VS_FIXEDFILEINFO *ffInfo = NULL;
		UINT ffLen;

		if (versionString == NULL || versionStringLen < 1)
			return;
		versionString[0] = 0;
		if (!GetModuleFileNameA(handle, path, sizeof(path)))
			return;

		length = GetFileVersionInfoSizeA(path, &tmp);
		if (length > 1024)
			length = 1024;

		if (GetFileVersionInfoA(path, 0, length, bytes))
		{
			ffLen = sizeof(VS_FIXEDFILEINFO);
			if (VerQueryValueA(bytes, (char*)"\\", (void**)&ffInfo, &ffLen) && ffInfo != NULL)
			{
#ifdef HAVE__SNPRINTF_S
				_snprintf_s(versionString, versionStringLen, versionStringLen, "Version %d.%d", HIWORD(ffInfo->dwProductVersionMS), LOWORD(ffInfo->dwProductVersionMS));
#else
				snprintf(versionString, versionStringLen, "Version %d.%d", HIWORD(ffInfo->dwProductVersionMS), LOWORD(ffInfo->dwProductVersionMS));
#endif
			}
			else
			{
#ifdef HAVE__SNPRINTF_S
				_snprintf_s(versionString, versionStringLen, versionStringLen, "unknown version");
#else
				snprintf(versionString, versionStringLen, "unknown version");
#endif
			}
		}
		else
		{
#ifdef HAVE__SNPRINTF_S
			_snprintf_s(versionString, versionStringLen, versionStringLen, "unknown version");
#else
			snprintf(versionString, versionStringLen, "unknown version");
#endif
		}
	}

	// 06/14/2010 KRR unreferenced local parameter
	static INT_PTR CALLBACK	AboutCkmProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM /*lParam*/)
	{
		switch (msg)
		{
		case WM_INITDIALOG:
		{
			const int nMaxTextLen = 1024;
			char pzText[nMaxTextLen];

			if (logo > (HBITMAP)1)
			{
				SendDlgItemMessageA(hWnd, IDC_TECSEC_LOGO, STM_SETIMAGE, IMAGE_BITMAP, LPARAM(logo));
			}
			LoadStringA((HINSTANCE)hDllInstance, IDS_APPTITLE, pzText, nMaxTextLen);
			SetDlgItemTextA(hWnd, IDC_APPTITLE, pzText);
			GetModuleVersion((HINSTANCE)hDllInstance, pzText, sizeof(pzText));
			SetDlgItemTextA(hWnd, IDC_VERSION, pzText);
			LoadStringA((HINSTANCE)hDllInstance, IDS_COPYRIGHT, pzText, nMaxTextLen);
			SetDlgItemTextA(hWnd, IDC_COPYRIGHT, pzText);
			LoadStringA((HINSTANCE)hDllInstance, IDS_PARTOF, pzText, nMaxTextLen);
			SetDlgItemTextA(hWnd, IDC_PARTOF, pzText);
			LoadStringA((HINSTANCE)hDllInstance, IDS_TRADEMARK, pzText, nMaxTextLen);
			SetDlgItemTextA(hWnd, IDC_TRADEMARK, pzText);
			LoadStringA((HINSTANCE)hDllInstance, IDS_WARNING, pzText, nMaxTextLen);
			SetDlgItemTextA(hWnd, IDC_WARNING, pzText);
			LoadStringA((HINSTANCE)hDllInstance, IDS_PATENTS, pzText, nMaxTextLen);
			SetDlgItemTextA(hWnd, IDC_PATENTS, pzText);

			/*
			m_bInitialized = true;

			if(!::SetForegroundWindow(m_hWnd))
			{
			HWND theForegroundWnd = ::GetForegroundWindow();

			if(theForegroundWnd == NULL)
			theForegroundWnd = ::FindWindow("Shell_TrayWnd",NULL);

			DWORD theFGWndThreadID = GetWindowThreadProcessId(theForegroundWnd,NULL);

			// Attach your thread to the foreground window thread
			if ( AttachThreadInput( theFGWndThreadID, GetCurrentThreadId(),true) )
			{
			// Send your dialog or window to the front
			::SetForegroundWindow( m_hWnd );

			// Detach your thread from the foreground window thread
			AttachThreadInput( theFGWndThreadID, GetCurrentThreadId(),false);
			}
			}
			*/
		}
		return (INT_PTR)TRUE;

		case WM_COMMAND:
			if (LOWORD(wParam) == IDOK)
			{
				EndDialog(hWnd, IDOK);
			}
			else if (LOWORD(wParam) == IDCANCEL)
			{
				EndDialog(hWnd, IDCANCEL);
			}
			return FALSE;
		}
		return FALSE;
	}
};

tsmod::IObject* CreateAboutCkm()
{
	return dynamic_cast<tsmod::IObject*>(new AboutCkm());
}