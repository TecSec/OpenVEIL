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
#include <CommCtrl.h>
#include "resource.h"
#include "HtmlHelp.h"

#pragma comment(lib, "htmlhelp.lib")

XP_MODULE hDllInstance = XP_MODULE_INVALID;
HBITMAP logo = NULL;
static ATOM registeredGrid = 0;
static ATOM registeredList = 0;

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID /*lpReserved*/
	)
{
	INITCOMMONCONTROLSEX icc;

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		hDllInstance = (XP_MODULE)hModule;

		icc.dwSize = sizeof(icc);
		icc.dwICC = ICC_HOTKEY_CLASS | ICC_ANIMATE_CLASS | ICC_BAR_CLASSES | ICC_DATE_CLASSES | ICC_LINK_CLASS |
			ICC_LISTVIEW_CLASSES | ICC_PAGESCROLLER_CLASS | ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES |
			ICC_TREEVIEW_CLASSES | ICC_UPDOWN_CLASS | ICC_USEREX_CLASSES;

		hDllInstance = (XP_MODULE)hModule;

		InitCommonControlsEx(&icc);

		registeredList = TSListInstall(hModule);
		registeredGrid = GridInstall(hModule);
		logo = LoadBitmap(hModule, MAKEINTRESOURCE(IDB_TECSECLOGO));
		if (logo == NULL)
			logo = (HBITMAP)1;
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		if (logo > (HBITMAP)1)
			DeleteObject(logo);
		logo = NULL;
		if (registeredGrid)
		{
			UnregisterClassA((const char *)(INT_PTR)registeredGrid, hModule);
			registeredGrid = 0;
		}
		if (registeredList)
		{
			UnregisterClassA((const char *)(INT_PTR)registeredList, hModule);
			registeredList = 0;
		}
		break;
	}
	return TRUE;
}

static bool Terminate()
{
	if (!HasServiceLocator())
		return true;

	std::shared_ptr<tsmod::IServiceLocator> servLoc = ::TopServiceLocator();

	servLoc->DeleteClass("/WinAPI/AudienceSelector");
	servLoc->DeleteClass("/WinAPI/FavoriteEditor");
	servLoc->DeleteClass("/WinAPI/AttributeSelectorGrid");
	servLoc->DeleteClass("/WinAPI/TokenLogIn");
	servLoc->DeleteClass("/WinAPI/AboutCkm");
	servLoc->DeleteClass("/WinAPI/KeyVEILLogIn");
	servLoc->DeleteClass("/WinAPI/TokenSelector");
	servLoc->DeleteClass("/WinAPI/FavoriteName");
	servLoc->DeleteClass("/WinAPI/ProgressDlg");
	servLoc->DeleteClass("/WinAPI/CreateVEILPropertySheet");
	servLoc->DeleteClass("/WinAPI/HelpRegistry");

	return true;
}
bool InitializeVEILWinAPI()
{
	std::shared_ptr<tsmod::IServiceLocator> servLoc = ::TopServiceLocator();

	if (!servLoc->CanCreate("/WinAPI/AudienceSelector"))
	{
		servLoc->AddClass("/WinAPI/AudienceSelector", CreateAudienceSelector);
		servLoc->AddClass("/WinAPI/FavoriteEditor", CreateFavoriteEditer);
		servLoc->AddClass("/WinAPI/AttributeSelectorGrid", CreateAttributeSelectorGrid);
		servLoc->AddClass("/WinAPI/TokenLogIn", CreateTokenLogIn);
		servLoc->AddClass("/WinAPI/AboutCkm", CreateAboutCkm);
		servLoc->AddClass("/WinAPI/KeyVEILLogIn", CreateKeyVEILLogIn);
		servLoc->AddClass("/WinAPI/TokenSelector", CreateTokenSelector);
		servLoc->AddClass("/WinAPI/FavoriteName", CreateFavoriteName);
		servLoc->AddClass("/WinAPI/ProgressDlg", CreateProgressDlg);
		servLoc->AddClass("/WinAPI/PropertySheet", CreateVEILPropertySheet);
		servLoc->AddSingletonClass("/WinAPI/HelpRegistry", CreateHelpRegistry);
		AddSystemTerminationFunction(Terminate);
	}
	return true;
}

XP_WINDOW TS_HtmlHelp(XP_WINDOW hwndCaller, const tscrypto::tsCryptoString& pszFile, UINT uCommand, DWORD_PTR dwData)
{
	//tscrypto::tsCryptoString tmp;

	//tmp << "File:  " << pszFile << endl << "command:  " << uCommand << endl << "data:  " << (int64_t)dwData << endl;
	//MessageBox(nullptr, tmp.c_str(), "DIAG", MB_OK);
#ifdef __GNUC__
	MessageBox((HWND)hwndCaller, "Sorry.  Help is not currently supported when using GCC", "ERROR", MB_OK);
	return XP_WINDOW_INVALID;
#else
	return (XP_WINDOW)HtmlHelpA((HWND)hwndCaller, pszFile.c_str(), uCommand, dwData);
#endif
}

//typedef HWND(__stdcall * helpFn)(HWND hwndCaller, LPCSTR pszFile, UINT uCommand, DWORD_PTR dwData);
//
//static HINSTANCE gHelpLib = NULL;
//static helpFn gHelpFn = NULL;
//
//XP_WINDOW TS_HtmlHelp(XP_WINDOW hwndCaller, const tscrypto::tsCryptoString& pszFile, UINT uCommand, DWORD_PTR dwData)
//{
//	if (gHelpLib == NULL)
//	{
//		gHelpLib = LoadLibraryA(("hhctrl.ocx"));
//		if (gHelpLib == NULL)
//		{
//			MessageBox(nullptr, "An error occurred while attempting to display the HTML help.  The Microsoft Help Viewer was not found.", "Error", MB_OK);
//			return XP_WINDOW_INVALID;
//		}
//		gHelpFn = (helpFn)GetProcAddress(gHelpLib, "HtmlHelpA");
//		if (gHelpFn == NULL)
//		{
//			MessageBox(nullptr, "An error occurred while attempting to display the HTML help.  The Microsoft Help Viewer did not have the required functionality.", "Error", MB_OK);
//			FreeLibrary(gHelpLib);
//			gHelpLib = NULL;
//			return XP_WINDOW_INVALID;
//		}
//	}
//
//	tscrypto::tsCryptoString tmp;
//
//	tmp << "File:  " << pszFile << endl << "command:  " << uCommand << endl << "data:  " << (int64_t)dwData << endl;
//	MessageBox(nullptr, tmp.c_str(), "DIAG", MB_OK);
//
//	return (XP_WINDOW)gHelpFn((HWND)hwndCaller, pszFile.c_str(), uCommand, dwData);
//}
