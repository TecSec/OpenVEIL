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

#ifndef __VEILWXWIDGETS_H__
#define __VEILWXWIDGETS_H__

#pragma once

#include "VEILCmsHeader.h"

#undef DECLARE_CLASS

#ifdef _WIN32
	#ifdef _STATIC_RUNTIME_LOADER
		#define VEILWXWIDGETS_EXPORT
		#define VEILWXWIDGETS_TEMPLATE_EXTERN extern
	#else
		#if !defined(VEILWXWIDGETSDEF) && !defined(DOXYGEN)
			#define VEILWXWIDGETS_EXPORT  __declspec(dllimport)
			#define VEILWXWIDGETS_TEMPLATE_EXTERN extern
		#else // _STATIC_RUNTIME_LOADER
			/// <summary>A macro that defines extern syntax for templates.</summary>
			#define VEILWXWIDGETS_TEMPLATE_EXTERN
			/// <summary>A macro that defines the export modifiers for the AppPlatform components.</summary>
			#define VEILWXWIDGETS_EXPORT __declspec(dllexport)
		#endif // !defined(VEILWXWIDGETSDEF) && !defined(DOXYGEN)
	#endif // _STATIC_RUNTIME_LOADER
#else // _WIN32
	#if !defined(VEILWXWIDGETSDEF) && !defined(DOXYGEN)
		#define VEILWXWIDGETS_EXPORT
		#define VEILWXWIDGETS_TEMPLATE_EXTERN extern
	#else
		#define VEILWXWIDGETS_EXPORT EXPORT_SYMBOL
		#define VEILWXWIDGETS_TEMPLATE_EXTERN
	#endif // !defined(VEILWXWIDGETSDEF) && !defined(DOXYGEN)
#endif // _WIN32

#define WXUSINGDLL 1

#include "wx/wxprec.h"

#ifdef __BORLANDC__
#pragma hdrstop
#endif

#ifndef WX_PRECOMP
#include "wx/wx.h"
#endif

#include "wx/apptrait.h"
#include "wx/datetime.h"
#include "wx/filename.h"
#include "wx/image.h"
#include "wx/bookctrl.h"
#include "wx/artprov.h"
#include "wx/imaglist.h"
#include "wx/minifram.h"
#include "wx/sysopt.h"
#include "wx/notifmsg.h"
#include "wx/modalhook.h"

#if wxUSE_RICHMSGDLG
#include "wx/richmsgdlg.h"
#endif // wxUSE_RICHMSGDLG

#if wxUSE_COLOURDLG
#include "wx/colordlg.h"
#endif // wxUSE_COLOURDLG

#if wxUSE_CHOICEDLG
#include "wx/choicdlg.h"
#endif // wxUSE_CHOICEDLG

#include "wx/rearrangectrl.h"
#include "wx/addremovectrl.h"

#if wxUSE_STARTUP_TIPS
#include "wx/tipdlg.h"
#endif // wxUSE_STARTUP_TIPS

#if wxUSE_PROGRESSDLG
#if wxUSE_STOPWATCH && wxUSE_LONGLONG
#include "wx/datetime.h"      // wxDateTime
#endif

#include "wx/progdlg.h"
#endif // wxUSE_PROGRESSDLG

#include "wx/appprogress.h"

#if wxUSE_ABOUTDLG
#include "wx/aboutdlg.h"

// these headers are only needed for custom about dialog
#include "wx/statline.h"
#include "wx/generic/aboutdlgg.h"
#endif // wxUSE_ABOUTDLG

#if wxUSE_BUSYINFO
#include "wx/busyinfo.h"
#endif // wxUSE_BUSYINFO

#if wxUSE_NUMBERDLG
#include "wx/numdlg.h"
#endif // wxUSE_NUMBERDLG

#if wxUSE_FILEDLG
#include "wx/filedlg.h"
#endif // wxUSE_FILEDLG

#if wxUSE_DIRDLG
#include "wx/dirdlg.h"
#endif // wxUSE_DIRDLG

#if wxUSE_FONTDLG
#include "wx/fontdlg.h"
#endif // wxUSE_FONTDLG

#if wxUSE_FINDREPLDLG
#include "wx/fdrepdlg.h"
#endif // wxUSE_FINDREPLDLG

#if wxUSE_INFOBAR
#include "wx/infobar.h"
#endif // wxUSE_INFOBAR

#include "wx/spinctrl.h"
#include "wx/propdlg.h"

#ifdef __WXUNIVERSAL__
#define USE_WXUNIVERSAL 1
#else
#define USE_WXUNIVERSAL 0
#endif

#ifdef WXUSINGDLL
#define USE_DLL 1
#else
#define USE_DLL 0
#endif

#if defined(__WXMSW__)
#define USE_WXMSW 1
#else
#define USE_WXMSW 0
#endif

#ifdef __WXMAC__
#define USE_WXMAC 1
#else
#define USE_WXMAC 0
#endif

#if USE_NATIVE_FONT_DIALOG_FOR_MACOSX
#define USE_WXMACFONTDLG 1
#else
#define USE_WXMACFONTDLG 0
#endif

#ifdef __WXGTK__
#define USE_WXGTK 1
#else
#define USE_WXGTK 0
#endif

#define USE_GENERIC_DIALOGS (!USE_WXUNIVERSAL && !USE_DLL)

#define USE_COLOURDLG_GENERIC \
    ((USE_WXMSW || USE_WXMAC) && USE_GENERIC_DIALOGS && wxUSE_COLOURDLG)
#define USE_DIRDLG_GENERIC \
    ((USE_WXMSW || USE_WXMAC) && USE_GENERIC_DIALOGS && wxUSE_DIRDLG)
#define USE_FILEDLG_GENERIC \
    ((USE_WXMSW || USE_WXMAC) && USE_GENERIC_DIALOGS  && wxUSE_FILEDLG)
#define USE_FONTDLG_GENERIC \
    ((USE_WXMSW || USE_WXMACFONTDLG) && USE_GENERIC_DIALOGS && wxUSE_FONTDLG)

// Turn USE_MODAL_PRESENTATION to 0 if there is any reason for not presenting difference
// between modal and modeless dialogs (ie. not implemented it in your port yet)
#if !wxUSE_BOOKCTRL
#define USE_MODAL_PRESENTATION 0
#else
#define USE_MODAL_PRESENTATION 1
#endif


// Turn USE_SETTINGS_DIALOG to 0 if supported
#if wxUSE_BOOKCTRL
#define USE_SETTINGS_DIALOG 1
#else
#define USE_SETTINGS_DIALOG 0
#endif

#if wxUSE_LOG

// Custom application traits class which we use to override the default log
// target creation
class MyAppTraits : public wxGUIAppTraits
{
public:
	virtual wxLog *CreateLogTarget() wxOVERRIDE;
};

#endif // wxUSE_LOG


#if USE_COLOURDLG_GENERIC
#include "wx/generic/colrdlgg.h"
#endif // USE_COLOURDLG_GENERIC

#if USE_DIRDLG_GENERIC
#include "wx/generic/dirdlgg.h"
#endif // USE_DIRDLG_GENERIC

#if USE_FILEDLG_GENERIC
#include "wx/generic/filedlgg.h"
#endif // USE_FILEDLG_GENERIC

#if USE_FONTDLG_GENERIC
#include "wx/generic/fontdlgg.h"
#endif // USE_FONTDLG_GENERIC


extern bool VEILWXWIDGETS_EXPORT InitializeVEILWxWidgets();

struct __XP_WINDOW{};
typedef ID<__XP_WINDOW, wxWindow*, nullptr> XP_WINDOW;
#define XP_WINDOW_INVALID XP_WINDOW::invalid()  /*!< \brief A flag that indicates that the window handle is invalid */

//#include "htmlhelp.h"

class IVEILWxUIBase
{
public:
	virtual ~IVEILWxUIBase(){}
	/// <summary>Destroys the window.</summary>
	virtual bool Destroy() = 0;
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
class IAudienceSelector : public IVEILWxUIBase
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
class IAttributeSelector : public IVEILWxUIBase
{
public:
	virtual bool Start(std::shared_ptr<IKeyVEILSession> session, XP_WINDOW parent, const GUID& CryptoGroupId, std::shared_ptr<ICmsHeaderAttributeGroup> group, std::shared_ptr<ICmsHeaderAttributeListExtension> attrList) = 0;
};

// "/WinAPI/TokenLogIn"
class ITokenLogin : public IVEILWxUIBase
{
public:
	virtual bool Start(std::shared_ptr<IKeyVEILSession> session, XP_WINDOW parent) = 0;
	virtual tscrypto::tsCryptoString Pin() = 0;
	virtual void Pin(const tscrypto::tsCryptoString& setTo) = 0;
};

// "/WinAPI/KeyVEILLogIn"
class IKeyVEILLogin : public IVEILWxUIBase
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
class ITokenSelector : public IVEILWxUIBase
{
public:
	virtual bool Start(std::shared_ptr<IKeyVEILConnector> connector, const GUID& enterpriseId, const tscrypto::tsCryptoString& reason, XP_WINDOW parent) = 0;
	virtual std::shared_ptr<IKeyVEILSession> Session() = 0;
};

// "/WinAPI/FavoriteName"
class IFavoriteName : public IVEILWxUIBase
{
public:
	virtual bool Start(XP_WINDOW parent) = 0;
	virtual tscrypto::tsCryptoString Name() = 0;
	virtual void Name(const tscrypto::tsCryptoString& setTo) = 0;
};

// "/WinAPI/ProgressDlg"
class IProgressDlg : public IVEILWxUIBase
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
	virtual bool showWindow(BOOL bShow) = 0;
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

//extern XP_WINDOW VEILWXWIDGETS_EXPORT TS_HtmlHelp(XP_WINDOW hwndCaller, const tscrypto::tsCryptoString& pszFile, UINT uCommand, DWORD_PTR dwData);

class IVEILPropertySheet;

class IVEILPropertyPage 
{
public:
	typedef enum { Invalid, Invalid_SamePage, NoError } PPResult;

	virtual ~IVEILPropertyPage() {}
	virtual tscrypto::tsCryptoString Title() const = 0;
	virtual void SetParent(std::shared_ptr<IVEILPropertySheet> parentSheet) = 0;
	virtual XP_WINDOW CreatePage(XP_WINDOW parentWindow) = 0;
	virtual bool Destroy() = 0;

	virtual void OnHelp() = 0;
	// called when the user presses OK, Close or Apply and allows the page to commit changes.
	// Return results of the apply
	virtual PPResult Apply() = 0;
	// Notification that the page is about to lose focus
	// Return true to block the change of page
	virtual bool KillActive() = 0;
	// Indicates that the user has pressed cancel
	// Return true to cancel the operation
	virtual bool QueryCancel() = 0;
	// Sent to the page to set the initial control focus
	virtual bool QueryInitialFocus() = 0;
	// Notification that the page is about to be destroyed
	virtual bool Reset() = 0;
	// Notification that the page is about to become active
	// Return true to cancel the activation
	virtual bool SetActive() = 0;
};

// "/WinAPI/PropertySheet"
class IVEILPropertySheet
{
public:
	typedef enum {VEILFileSettings, GeneralSettings} StandardPropPage;
	typedef enum { Standard, ToolBook, ButtonToolBook } PropertySheetType;

	virtual int DisplayModal(XP_WINDOW parent, PropertySheetType type = Standard) = 0;
	virtual void AddStandardPage(StandardPropPage page) = 0;
	virtual void AddCustomPage(const tscrypto::tsCryptoString& link) = 0;
	virtual std::shared_ptr<BasicVEILPreferences> BasicPreferences() = 0;
	virtual void PageModified(bool setTo) = 0;
};


#endif // __VEILWXWIDGETS_H__
