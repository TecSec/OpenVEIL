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

#ifndef __VEILWXWIDGETS_H__
#define __VEILWXWIDGETS_H__

#pragma once

#undef DECLARE_CLASS

#ifdef VEILWXWIDGETS_STATIC
#   define VEILWXWIDGETS_EXPORT
#   define VEILWXWIDGETS_TEMPLATE_EXTERN 
#else
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
#endif // VEILWXWIDGETS_STATIC

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

class VEILWXWIDGETS_EXPORT IVEILWxUIBase
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

// "/WxWin/AboutCKM"
class VEILWXWIDGETS_EXPORT IAboutCkm : public IVEILWxUIBase
{
public:
	virtual bool Start(XP_WINDOW parent, const tscrypto::tsCryptoString& appName) = 0;
};

class VEILWXWIDGETS_EXPORT ISkippablePage
{
public:
	virtual ~ISkippablePage()
	{
	}
	virtual bool skipMe() = 0;
};

// "/WxWin/AudienceSelector"
class VEILWXWIDGETS_EXPORT IAudienceSelector : public IVEILWxUIBase
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

	virtual void HideKeyVEILLogin(bool setTo) = 0;
};

#define TS_UI_CRYPTO_GROUP_ID_NOT_SPECIFIED GUID_NULL

// "/WxWin/AttributeSelectorGrid"
class VEILWXWIDGETS_EXPORT IAttributeSelector : public IVEILWxUIBase
{
public:
	virtual bool Start(std::shared_ptr<IKeyVEILSession> session, XP_WINDOW parent, const tscrypto::tsCryptoData& CryptoGroupId, std::shared_ptr<ICmsHeaderAttributeGroup> group, std::shared_ptr<ICmsHeaderAttributeListExtension> attrList) = 0;
};

// "/WxWin/TokenLogIn"
class VEILWXWIDGETS_EXPORT ITokenLogin : public IVEILWxUIBase
{
public:
	virtual bool Start(std::shared_ptr<IKeyVEILSession> session, XP_WINDOW parent) = 0;
	virtual tscrypto::tsCryptoString Pin() = 0;
	virtual void Pin(const tscrypto::tsCryptoString& setTo) = 0;
};

// "/WxWin/KeyVEILLogIn"
class VEILWXWIDGETS_EXPORT IKeyVEILLogin : public IVEILWxUIBase
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

// "/WxWin/TokenSelector"
class VEILWXWIDGETS_EXPORT ITokenSelector : public IVEILWxUIBase
{
public:
	virtual bool Start(std::shared_ptr<IKeyVEILConnector> connector, const GUID& enterpriseId, const tscrypto::tsCryptoString& reason, XP_WINDOW parent) = 0;
	virtual std::shared_ptr<IKeyVEILSession> Session() = 0;
};

// "/WxWin/FavoriteName"
class VEILWXWIDGETS_EXPORT IFavoriteName : public IVEILWxUIBase
{
public:
	virtual bool Start(XP_WINDOW parent) = 0;
	virtual tscrypto::tsCryptoString Name() = 0;
	virtual void Name(const tscrypto::tsCryptoString& setTo) = 0;
};

// "/WxWin/ProgressDlg"
class VEILWXWIDGETS_EXPORT IProgressDlg : public IVEILWxUIBase
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

class IVEILPropertySheet;

class VEILWXWIDGETS_EXPORT IVEILPropertyPage
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

// "/WxWin/PropertySheet"
class VEILWXWIDGETS_EXPORT IVEILPropertySheet
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

// "/WxWin/EnterPin"
class VEILWXWIDGETS_EXPORT IEnterPin : public IVEILWxUIBase
{
public:
	typedef enum {enterPin, createPin, changePin} EnterPinMode;
	
	virtual void SetExplanation(const tscrypto::tsCryptoString& setTo) = 0;
	virtual void SetStatus(const tscrypto::tsCryptoString& setTo) = 0;
	virtual void SetPinTesterFunction(std::function<bool(std::shared_ptr<IEnterPin>, const tscrypto::tsCryptoString&)> func) = 0;
	virtual void SetPinStrengthFunction(std::function<int(std::shared_ptr<IEnterPin>, const tscrypto::tsCryptoString&)> func) = 0;
	virtual void SetMinimumLength(uint32_t setTo) = 0;
	virtual void SetMaximumLength(uint32_t setTo) = 0;
	virtual uint32_t GetWeakStrength() const = 0;
	virtual void SetWeakStrength(uint32_t setTo) = 0;
	virtual uint32_t GetStrongStrength() const = 0;
	virtual void SetStrongStrength(uint32_t setTo) = 0;
	virtual uint32_t GetMaxStrength() const = 0;
	virtual void SetMaxStrength(uint32_t setTo) = 0;

	virtual bool Start(const tscrypto::tsCryptoString& title, EnterPinMode mode, XP_WINDOW parent) = 0;
	virtual tscrypto::tsCryptoString Pin() = 0;
	virtual void Pin(const tscrypto::tsCryptoString& setTo) = 0;
	virtual tscrypto::tsCryptoString OldPin() = 0;
	virtual void OldPin(const tscrypto::tsCryptoString& setTo) = 0;
	virtual void SetHelpId(uint32_t setTo) = 0;
};

// "/WxWin/ChangeName"
class VEILWXWIDGETS_EXPORT IChangeName : public IVEILWxUIBase
{
public:
	virtual tscrypto::tsCryptoString Description() = 0;
	virtual void Description(const tscrypto::tsCryptoString& setTo) = 0;
	virtual tscrypto::tsCryptoString OldName() = 0;
	virtual void OldName(const tscrypto::tsCryptoString& setTo) = 0;
	virtual bool Start(XP_WINDOW parent, uint32_t helpId) = 0;
	virtual tscrypto::tsCryptoString NewName() = 0;
	virtual void NewName(const tscrypto::tsCryptoString& setTo) = 0;
};

int VEILWXWIDGETS_EXPORT wxTsMessageBox(const tscrypto::tsCryptoString& message, const tscrypto::tsCryptoString& caption, long style = wxOK, XP_WINDOW parent = XP_WINDOW_INVALID);


#define WEAK_PASSWORD_ENTROPY 32
#define STRONG_PASSWORD_ENTROPY 60

class VEILWXWIDGETS_EXPORT PasswordGauge : public wxWindow {
public:
	PasswordGauge() :
		m_position(0), m_max(100), m_label(false), m_weak(32), m_strong(60) {
		InitialInit();
	}

	PasswordGauge(wxWindow *parent, wxWindowID id, const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = 0, const wxString& name = wxPanelNameStr) :
		wxWindow(parent, id, pos, size, style, name), m_position(0), m_max(100), m_label(false), m_weak(32), m_strong(60)
	{
		InitialInit();
	}

	~PasswordGauge()
	{
		Unbind(wxEVT_SIZE, &PasswordGauge::OnPanelResize, this);
		Unbind(wxEVT_PAINT, &PasswordGauge::paintEvent, this);
	}

	void paintEvent(wxPaintEvent & evt)
	{
		wxPaintDC dc(this);
		render(dc);
	}
	void render(wxPaintDC& dc)
	{
		int value = GetValue();

		dc.Clear();

		// Set default font
		dc.SetFont(m_font);
		dc.SetTextForeground(m_font_col);


		// Draw gauge background
		dc.SetBrush(m_backFill);
		dc.SetPen(m_pen);

		wxRect FillRect(0, 0, dc.GetSize().GetWidth(), dc.GetSize().GetHeight());
		dc.DrawRectangle(FillRect);

		if (value > GetMax())
			value = GetMax();
		if (value < 0)
			value = 0;
		// Draw gauge bar
		if (value >= GetStrong())
			dc.SetBrush(m_foreFill3);
		else if (value >= GetWeak())
			dc.SetBrush(m_foreFill2);
		else
			dc.SetBrush(m_foreFill1);

		wxCoord w = dc.GetSize().GetWidth() * value / GetMax();
		wxCoord h = dc.GetSize().GetHeight();

		wxRect rectToDraw(0, 0, w, h);
		dc.DrawRectangle(rectToDraw);

		if (value > 0)
		{
			if (m_label) {

				const wxFont currentFont = dc.GetFont();
				int fw = currentFont.GetPointSize();
				tscrypto::tsCryptoString tmp;

				tmp.Format("Strength: %d", GetValue());

				dc.DrawText(tmp.c_str(), (dc.GetSize().GetWidth() - dc.GetTextExtent(tmp.c_str()).GetWidth()) / 2, dc.GetSize().GetHeight() / 2 - fw / 1.25);
			}
			else {
				const wxFont currentFont = dc.GetFont();
				int fw = currentFont.GetPointSize();
				tscrypto::tsCryptoString tmp;

				if (value >= GetStrong())
					tmp = "strong";
				else if (value >= GetWeak())
					tmp = "weak";
				else
					tmp = "very weak";

				dc.DrawText(tmp.c_str(), (dc.GetSize().GetWidth() - dc.GetTextExtent(tmp.c_str()).GetWidth()) / 2, dc.GetSize().GetHeight() / 2 - fw / 1.25);
			}
		}
	}

	// Setters & Getters

	int GetValue() const { return m_position; }
	int GetWeak() const { return m_weak; }
	int GetStrong() const { return m_strong; }
	int GetMax() const { return m_max; }

	void SetValue(int pos)
	{
		if (GetValue() != pos)
		{
			m_position = pos;
			Refresh();
			Update();
		}
	}
	void SetMax(int setTo)
	{
		if (GetMax() != setTo)
		{
			m_max = setTo;
			Refresh();
			Update();
		}
	}
	void SetWeak(int setTo)
	{
		if (GetWeak() != setTo)
		{
			m_weak = setTo;
			Refresh();
			Update();
		}
	}
	void SetStrong(int setTo)
	{
		if (GetStrong() != setTo)
		{
			m_strong = setTo;
			Refresh();
			Update();
		}
	}

	// Settings

	void ShowEntropy(bool flag) { m_label = flag; }
	void SetBackgroundBrush(const wxColour& col) { m_backFill.SetColour(col); }
	void SetPoorForegroundBrush(const wxColour& col) { m_foreFill1.SetColour(col); }
	void SetWeakForegroundBrush(const wxColour& col) { m_foreFill2.SetColour(col); }
	void SetStrongForegroundBrush(const wxColour& col) { m_foreFill3.SetColour(col); }
	void SetPen(const wxPen& pen) { m_pen = pen; }
	bool SetFont(const wxFont &font) { m_font = font; return true; }
	void SetTextForeground(const wxColour &colour) { m_font_col = colour; }


private:
	int         m_position; // Current position
	int         m_max;      // Overall range
	int         m_weak;     // Point where it changes to weak
	int         m_strong;   // Point where it changes to strong 

	bool        m_label;    // If true, then add entropy value label

	wxBrush     m_backFill; // Gauge background brush
	wxBrush     m_foreFill1; // Gauge bar brush
	wxBrush     m_foreFill2; // Gauge bar brush
	wxBrush     m_foreFill3; // Gauge bar brush
	wxPen       m_pen;      // For gauge border drawing

	wxFont      m_font;     // Text font
	wxColour    m_font_col; // Text colour

							// Brushes and pen init
	void InitialInit()
	{
		// White background by default
		m_backFill.SetColour("WHITE");

		// Light grey gauge bar by default
		m_foreFill1.SetColour("RED");
		m_foreFill2.SetColour("YELLOW");
		m_foreFill3.SetColour("GREEN");

		// Solid brushes by default
		m_backFill.SetStyle(wxBRUSHSTYLE_SOLID);
		m_foreFill1.SetStyle(wxBRUSHSTYLE_SOLID);
		m_foreFill2.SetStyle(wxBRUSHSTYLE_SOLID);
		m_foreFill3.SetStyle(wxBRUSHSTYLE_SOLID);

		// Default gauge border: black 1px solid
		m_pen.SetColour("BLACK");
		m_pen.SetWidth(1);
		m_pen.SetStyle(wxPENSTYLE_SOLID);

		// Set default font
		m_font = *wxNORMAL_FONT;
		m_font_col = *wxBLACK;

		// Binds redraw on resize event
		Bind(wxEVT_SIZE, &PasswordGauge::OnPanelResize, this);
		Bind(wxEVT_PAINT, &PasswordGauge::paintEvent, this);
	}
	// Resize event handler
	void OnPanelResize(wxSizeEvent& event)
	{
		Update();
		event.Skip();
	}
};

const size_t helpid_TOC = 0;

const size_t winid_AudienceSelector = 1;
const size_t winid_GeneralSettings = 2;
const size_t winid_FileSettings = 3;
const size_t winid_TokenSelector = 4;
const size_t winid_KeyVEILLogin = 5;
const size_t winid_FavoriteManager = 6;
const size_t winid_FavoriteName = 7;
const size_t winid_AttributeSelector = 8;
const size_t winid_FavoriteSelectionPage = 9;
const size_t winid_GroupEditorPage = 10;
const size_t winid_KeyVEILLoginPage = 11;
const size_t winid_SaveFavoritePage = 12;
const size_t winid_TokenSelectionPage = 13;
const size_t winid_ChangeFavoriteName = 14;
const size_t winid_StandardTokenLogin = 15;

const size_t winid_FavAdd_FavoriteSelectionPage = 16;
const size_t winid_FavAdd_GroupEditorPage = 17;
const size_t winid_FavAdd_KeyVEILLoginPage = 18;
const size_t winid_FavAdd_SaveFavoritePage = 19;
const size_t winid_FavAdd_TokenSelectionPage = 20;

const size_t winid_FavEdit_FavoriteSelectionPage = 21;
const size_t winid_FavEdit_GroupEditorPage = 22;
const size_t winid_FavEdit_KeyVEILLoginPage = 23;
const size_t winid_FavEdit_SaveFavoritePage = 24;
const size_t winid_FavEdit_TokenSelectionPage = 25;

class VEILWXWIDGETS_EXPORT IVEILHttpHelpRegistry
{
public:
	virtual ~IVEILHttpHelpRegistry() {}
	virtual void DisplayHelpForWindowId(size_t windowId, XP_WINDOW wnd) = 0;
	virtual void RegisterHelpFunction(size_t windowId, std::function<void()> func) = 0;
	virtual void RegisterHttpHelp(size_t windowId, const tscrypto::tsCryptoString& urlPart) = 0;
	virtual void SetHelpPort(uint16_t setTo) = 0;
	virtual void SetHelpScheme(const tscrypto::tsCryptoString& scheme) = 0;
	virtual void SetHelpPrefix(const tscrypto::tsCryptoString& setTo) = 0;
};


#endif // __VEILWXWIDGETS_H__
