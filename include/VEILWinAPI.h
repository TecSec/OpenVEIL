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

#ifndef __VEILWINAPI_H__
#define __VEILWINAPI_H__

#pragma once

#ifdef _WIN32
#ifdef _STATIC_RUNTIME_LOADER
#define VEILWINAPI_EXPORT
#define VEILWINAPI_TEMPLATE_EXTERN extern
#else
#if !defined(VEILWINAPIDEF) && !defined(DOXYGEN)
#define VEILWINAPI_EXPORT  __declspec(dllimport)
#define VEILWINAPI_TEMPLATE_EXTERN extern
#else // _STATIC_RUNTIME_LOADER
/// <summary>A macro that defines extern syntax for templates.</summary>
#define VEILWINAPI_TEMPLATE_EXTERN
/// <summary>A macro that defines the export modifiers for the AppPlatform components.</summary>
#define VEILWINAPI_EXPORT __declspec(dllexport)
#endif // !defined(VEILWINAPIDEF) && !defined(DOXYGEN)
#endif // _STATIC_RUNTIME_LOADER
#else // _WIN32
#if !defined(VEILWINAPIDEF) && !defined(DOXYGEN)
#define VEILWINAPI_EXPORT
#define VEILWINAPI_TEMPLATE_EXTERN extern
#else
#define VEILWINAPI_EXPORT EXPORT_SYMBOL
#define VEILWINAPI_TEMPLATE_EXTERN
#endif // !defined(VEILWINAPIDEF) && !defined(DOXYGEN)
#endif // _WIN32

extern bool VEILWINAPI_EXPORT InitializeVEILWinAPI();

struct __xp_window{};
#ifdef _WIN32
typedef ID<__xp_window, HWND, nullptr> XP_WINDOW;
#else
typedef ID<__xp_window, void*, nullptr> XP_WINDOW;
#endif // _WIN32
#define XP_WINDOW_INVALID XP_WINDOW::invalid()  /*!< \brief A flag that indicates that the window handle is invalid */

#include "WinAPI/htmlhelp.h"

class VEILWINAPI_EXPORT IVEILUIBase
{
public:
	virtual ~IVEILUIBase(){}
	/// <summary>Destroys the window.</summary>
	virtual void Destroy() = 0;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Displays the window as a modal dialog.</summary>
	///
	/// <returns>The return code from the dialog.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual int  DisplayModal() = 0;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Displays the window as a modal dialog parented to the specified window.</summary>
	///
	/// <param name="wnd">The parent window.</param>
	///
	/// <returns>The return code from the dialog.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual int  DisplayModal(XP_WINDOW wnd) = 0;
};

// "/WinAPI/AudienceSelector"
class VEILWINAPI_EXPORT IAudienceSelector : public IVEILUIBase
{
public:
	virtual std::shared_ptr<IKeyVEILConnector> Connector() = 0;
	virtual void Connector(std::shared_ptr<IKeyVEILConnector> setTo) = 0;
	virtual std::shared_ptr<IKeyVEILSession> Session() = 0;
	virtual void Session(std::shared_ptr<IKeyVEILSession> setTo) = 0;
	virtual tscrypto::tsCryptoData HeaderData() = 0;
	virtual void HeaderData(const tscrypto::tsCryptoData& setTo) = 0;
	virtual std::shared_ptr<ICmsHeader> Header() = 0;
	virtual void Header(std::shared_ptr<ICmsHeader> setTo) = 0;

	virtual bool Start(std::shared_ptr<IKeyVEILConnector> connector, XP_WINDOW parent, const tscrypto::tsCryptoString& appName) = 0;

};

#define TS_UI_CRYPTO_GROUP_ID_NOT_SPECIFIED GUID_NULL

// "/WinAPI/AttributeSelectorGrid"
class VEILWINAPI_EXPORT IAttributeSelector : public IVEILUIBase
{
public:
	virtual bool Start(std::shared_ptr<IKeyVEILSession> session, XP_WINDOW parent, const tscrypto::tsCryptoData& CryptoGroupId, std::shared_ptr<ICmsHeaderAttributeGroup> group, std::shared_ptr<ICmsHeaderAttributeListExtension> attrList) = 0;
};

// "/WinAPI/TokenLogIn"
class VEILWINAPI_EXPORT ITokenLogin : public IVEILUIBase
{
public:
	virtual bool Start(std::shared_ptr<IKeyVEILSession> session, XP_WINDOW parent) = 0;
	virtual tscrypto::tsCryptoString Pin() = 0;
	virtual void Pin(const tscrypto::tsCryptoString& setTo) = 0;
};

// "/WinAPI/KeyVEILLogIn"
class VEILWINAPI_EXPORT IKeyVEILLogin : public IVEILUIBase
{
public:
	virtual bool Start(std::shared_ptr<IKeyVEILConnector> connector, XP_WINDOW parent) = 0;
	virtual std::shared_ptr<IKeyVEILConnector> Connector() = 0;
	virtual tscrypto::tsCryptoString Pin() = 0;
	virtual void Pin(const tscrypto::tsCryptoString& setTo) = 0;
	virtual tscrypto::tsCryptoString URL() = 0;
	virtual void URL(const tscrypto::tsCryptoString& setTo) = 0;
	virtual tscrypto::tsCryptoString UserName() = 0;
	virtual void UserName(const tscrypto::tsCryptoString& setTo) = 0;
};

// "/WinAPI/TokenSelector"
class VEILWINAPI_EXPORT ITokenSelector : public IVEILUIBase
{
public:
	virtual bool Start(std::shared_ptr<IKeyVEILConnector> connector, const GUID& enterpriseId, const tscrypto::tsCryptoString& reason, XP_WINDOW parent) = 0;
	virtual std::shared_ptr<IKeyVEILSession> Session() = 0;
};

// "/WinAPI/FavoriteName"
class VEILWINAPI_EXPORT IFavoriteName : public IVEILUIBase
{
public:
	virtual bool Start(XP_WINDOW parent) = 0;
	virtual tscrypto::tsCryptoString Name() = 0;
	virtual void Name(const tscrypto::tsCryptoString& setTo) = 0;
};

// "/WinAPI/ProgressDlg"
class VEILWINAPI_EXPORT IProgressDlg : public IVEILUIBase
{
public:
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Creates the progress dialog with the specified parent window.</summary>
	///
	/// <param name="pParent">The parent window.</param>
	///
	/// <returns>true if it succeeds, false if it fails.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool Create(XP_WINDOW pParent) = 0;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Shows the window.</summary>
	///
	/// <param name="bShow">true to show, false to hide.</param>
	///
	/// <returns>true if it succeeds, false if it fails.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool showWindow(bool bShow) = 0;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Determines if the cancel button was pressed.</summary>
	///
	/// <returns>true if it succeeds, false if it fails.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool CheckCancelButton() = 0;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Sets the range of the progress bar.</summary>
	///
	/// <param name="nLower">The lower end.</param>
	/// <param name="nUpper">The upper end.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual void SetRange(int nLower, int nUpper) = 0;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Sets the increment for the progress bar.</summary>
	///
	/// <param name="nStep">Amount to increment by.</param>
	///
	/// <returns>The old step number.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual int  SetStep(int nStep) = 0;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Gets the position of the progress bar.</summary>
	///
	/// <returns>The position.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual int  GetPos() = 0;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Sets the position of the progress bar.</summary>
	///
	/// <param name="nPos">The new position.</param>
	///
	/// <returns>The old position.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual int  SetPos(int nPos) = 0;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Increments the position of the progress bar.</summary>
	///
	/// <param name="nPos">The amount to increment.</param>
	///
	/// <returns>The new position of the progress bar.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual int  OffsetPos(int nPos) = 0;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Force the progress bar to step forward one notch</summary>
	///
	/// <returns>The new position of the progress bar.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual int  StepIt() = 0;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Sets the status text on the dialog.</summary>
	///
	/// <param name="sText">The text.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual void SetStatusText(const tscrypto::tsCryptoString& sText) = 0;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Sets the window title of the progress dialog.</summary>
	///
	/// <param name="sText">The text.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual void SetWindowTitle(const tscrypto::tsCryptoString& sText) = 0;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Displays a message described by sText.</summary>
	///
	/// <param name="sText">The text.</param>
	///
	/// <returns>ID_OK.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	//    virtual int  DisplayMessage(const tscrypto::tsCryptoString& sText) = 0;
	virtual int  DisplayMessage(const tscrypto::tsCryptoString& sText, int32_t lMB) = 0;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Sets the show percentage flag.</summary>
	///
	/// <param name="bShowPercent">true to show the percentage string, false to hide the percentage.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual void SetShowPercent(bool bShowPercent) = 0;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Enables the cancel button.</summary>
	///
	/// <param name="bShowCancel">true to show, false to hide the cancel.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual void EnableCancelButton(bool bShowCancel) = 0;
};

extern XP_WINDOW VEILWINAPI_EXPORT TS_HtmlHelp(XP_WINDOW hwndCaller, const tscrypto::tsCryptoString& pszFile, uint32_t uCommand, DWORD_PTR dwData);

// "/WinAPI/PropertySheet"
class VEILWINAPI_EXPORT IVEILPropertySheet : public IVEILUIBase
{
public:
	typedef enum {VEILFileSettings, GeneralSettings} StandardPropPage;
	virtual bool Start(XP_WINDOW parent) = 0;
	virtual void AddStandardPage(StandardPropPage page) = 0;
	virtual void AddCustomPage(HINSTANCE resourceModule, int64_t resourceId, std::function<int64_t(XP_WINDOW, uint32_t, uint64_t, uint64_t)> func, const tscrypto::tsCryptoString& title) = 0;
	virtual std::shared_ptr<BasicVEILPreferences> BasicPreferences() = 0;
};

const size_t helpid_TOC = 0;

const size_t winid_AudienceSelector = 1;
const size_t winid_GeneralSettings = 2;
const size_t winid_FileSettings = 3;
const size_t winid_TokenSelector = 4;

class VEILWINAPI_EXPORT IVEILHelpRegistry
{
public:
	virtual ~IVEILHelpRegistry() {}
	virtual void DisplayHelpForWindowId(size_t windowId, XP_WINDOW wnd) = 0;
	virtual void RegisterHelpFunction(size_t windowId, std::function<void()> func) = 0;
	virtual void RegisterCHMHelp(size_t windowId, const tscrypto::tsCryptoString& filename, size_t helpId) = 0;
};

#endif // __VEILWINAPI_H__
