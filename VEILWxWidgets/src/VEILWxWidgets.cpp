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
#include "tecseclogo.xpm"
#include "readwrit.xpm"

XP_MODULE hDllInstance = XP_MODULE_INVALID;
//HBITMAP logo = NULL;
//static ATOM registeredGrid = 0;
//static ATOM registeredList = 0;

#ifdef _WIN32
BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID /*lpReserved*/
	)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		hDllInstance = (XP_MODULE)hModule;
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
#endif

static bool Terminate()
{
	if (!HasServiceLocator())
		return true;

	std::shared_ptr<tsmod::IServiceLocator> servLoc = ::TopServiceLocator();

	servLoc->DeleteClass("/WxWin/AudienceSelector");
	servLoc->DeleteClass("/WxWin/FavoriteEditor");
	servLoc->DeleteClass("/WxWin/AttributeSelectorGrid");
	servLoc->DeleteClass("/WxWin/TokenLogIn");
	servLoc->DeleteClass("/WxWin/AboutCkm");
	servLoc->DeleteClass("/WxWin/KeyVEILLogIn");
	servLoc->DeleteClass("/WxWin/TokenSelector");
	servLoc->DeleteClass("/WxWin/FavoriteName");
	servLoc->DeleteClass("/WxWin/ProgressDlg");
	servLoc->DeleteClass("/WxWin/CreateVEILPropertySheet");
	servLoc->DeleteClass("/WxWin/GeneralSettingsPage");
	servLoc->DeleteClass("/WxWin/VEILFileSettingsPage");

	return true;
}
bool InitializeVEILWxWidgets()
{
	std::shared_ptr<tsmod::IServiceLocator> servLoc = ::TopServiceLocator();

	if (!servLoc->CanCreate("/WxWin/AudienceSelector"))
	{
#if wxUSE_XPM
		wxImage::AddHandler(new wxXPMHandler);
#endif
#if wxUSE_LIBPNG
		wxImage::AddHandler(new wxPNGHandler);
#endif
#if wxUSE_LIBJPEG
		wxImage::AddHandler(new wxJPEGHandler);
#endif
#if wxUSE_GIF
		wxImage::AddHandler(new wxGIFHandler);
#endif

		servLoc->AddClass("/WxWin/AudienceSelector", CreateAudienceSelector);
		servLoc->AddClass("/WxWin/FavoriteEditor", CreateFavoriteEditer);
		servLoc->AddClass("/WxWin/AttributeSelectorGrid", CreateAttributeSelectorGrid);
		servLoc->AddClass("/WxWin/TokenLogIn", CreateTokenLogIn);
		servLoc->AddClass("/WxWin/AboutCkm", CreateAboutCkm);
		servLoc->AddClass("/WxWin/KeyVEILLogIn", CreateKeyVEILLogIn);
		servLoc->AddClass("/WxWin/TokenSelector", CreateTokenSelector);
		servLoc->AddClass("/WxWin/FavoriteName", CreateFavoriteName);
		servLoc->AddClass("/WxWin/GeneralSettingsPage", CreateGeneralSettingsPage);
		servLoc->AddClass("/WxWin/VEILFileSettingsPage", CreateVEILFileSettingsPage);
		servLoc->AddClass("/WxWin/PropertySheet", CreateVEILPropertySheet);
		//servLoc->AddClass("/WxWin/ProgressDlg", CreateProgressDlg);
		AddSystemTerminationFunction(Terminate);
	}
	return true;
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
//	return (XP_WINDOW)gHelpFn((HWND)hwndCaller, pszFile.c_str(), uCommand, dwData);
//}


/// Retrieves bitmap resources
wxBitmap GetBitmapResource(const wxString& _name)
{
	wxString name(_name);

	name.Replace("../../src/", "");
	// Bitmap retrieval
	if (name == wxT("tecseclogo.xpm"))
	{
		wxBitmap bitmap(tecseclogo_xpm);
		return bitmap;
	}
	if (name == wxT("readwrit.xpm"))
	{
		wxBitmap bitmap(readwrit_xpm);
		return bitmap;
	}
	return wxNullBitmap;
}

/// Retrieves icon resources
wxIcon GetIconResource(const wxString& name)
{
	// Icon retrieval
	////@begin AboutCKM icon retrieval
	wxUnusedVar(name);
	return wxNullIcon;
	////@end AboutCKM icon retrieval
}
