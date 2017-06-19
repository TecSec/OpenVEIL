/////////////////////////////////////////////////////////////////////////////
// Name:        progressdlg.h
// Purpose:     
// Author:      Roger Butler
// Modified by: 
// Created:     15/02/2017 12:04:01
// RCS-ID:      
// Copyright:   Copyright (c) 2017, TecSec, Inc.  
// Licence:     
/////////////////////////////////////////////////////////////////////////////

#ifndef _PROGRESSDLG_H_
#define _PROGRESSDLG_H_


/*!
 * Includes
 */

////@begin includes
////@end includes

/*!
 * Forward declarations
 */

////@begin forward declarations
////@end forward declarations

/*!
 * Control identifiers
 */

////@begin control identifiers
#define ID_PROGRESSDLG 10000
#define ID_TASK_NAME 10020
#define ID_PROGRESS_GAUGE 10001
#define SYMBOL_PROGRESSDLG_STYLE wxDEFAULT_DIALOG_STYLE|wxCAPTION|wxTAB_TRAVERSAL
#define SYMBOL_PROGRESSDLG_TITLE _("Progress...")
#define SYMBOL_PROGRESSDLG_IDNAME ID_PROGRESSDLG
#define SYMBOL_PROGRESSDLG_SIZE wxSize(400, 110)
#define SYMBOL_PROGRESSDLG_POSITION wxDefaultPosition
////@end control identifiers


/*!
 * ProgressDlg class declaration
 */

class ProgressDlg: public wxDialog
{    
    DECLARE_DYNAMIC_CLASS( ProgressDlg )
    DECLARE_EVENT_TABLE()

public:
    /// Constructors
    ProgressDlg();
    ProgressDlg( wxWindow* parent, wxWindowID id = SYMBOL_PROGRESSDLG_IDNAME, const wxString& caption = SYMBOL_PROGRESSDLG_TITLE, const wxPoint& pos = SYMBOL_PROGRESSDLG_POSITION, const wxSize& size = SYMBOL_PROGRESSDLG_SIZE, long style = SYMBOL_PROGRESSDLG_STYLE );

    /// Creation
    bool Create( wxWindow* parent, wxWindowID id = SYMBOL_PROGRESSDLG_IDNAME, const wxString& caption = SYMBOL_PROGRESSDLG_TITLE, const wxPoint& pos = SYMBOL_PROGRESSDLG_POSITION, const wxSize& size = SYMBOL_PROGRESSDLG_SIZE, long style = SYMBOL_PROGRESSDLG_STYLE );

    /// Destructor
    ~ProgressDlg();

    /// Initialises member variables
    void Init();

    /// Creates the controls and sizers
    void CreateControls();

////@begin ProgressDlg event handler declarations

    /// wxEVT_INIT_DIALOG event handler for ID_PROGRESSDLG
    void OnInitDialog( wxInitDialogEvent& event );

    /// wxEVT_DESTROY event handler for ID_PROGRESSDLG
    void OnDestroy( wxWindowDestroyEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_CANCEL
    void OnCancelClick( wxCommandEvent& event );

////@end ProgressDlg event handler declarations

////@begin ProgressDlg member function declarations

    /// Retrieves bitmap resources
    wxBitmap GetBitmapResource( const wxString& name );

    /// Retrieves icon resources
    wxIcon GetIconResource( const wxString& name );
////@end ProgressDlg member function declarations

    /// Should we show tooltips?
    static bool ShowToolTips();

	void setTask(const char* taskName);
	void DisableOtherWindows();
	void ReenableOtherWindows();
	bool WasCancelled();
	void ClearCancel();
	void SetRange(int setTo);
	int GetValue();
	void SetValue(int setTo);

////@begin ProgressDlg member variables
    wxStaticText* _txtTask;
    wxGauge* _guage;
    wxButton* _btnCancel;
////@end ProgressDlg member variables

	wxWindowDisabler* m_winDisabler;
	wxWindow* m_parentTop;
	bool m_wasCancelled;
	int m_range;

protected:
	bool HasPDFlag(int flag) const { return (m_pdStyle & flag) != 0; }

	// Progress dialog styles: this is not the same as m_windowStyle because
	// wxPD_XXX constants clash with the existing TLW styles so to be sure we
	// don't have any conflicts we just use a separate variable for storing
	// them.
	int m_pdStyle;

};

#endif
    // _PROGRESSDLG_H_
