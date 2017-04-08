/////////////////////////////////////////////////////////////////////////////
// Name:        changenamedlg.h
// Purpose:     
// Author:      Roger Butler
// Modified by: 
// Created:     06/03/2017 16:19:40
// RCS-ID:      
// Copyright:   Copyright (c) 2017, TecSec, Inc.  
// Licence:     
/////////////////////////////////////////////////////////////////////////////

#ifndef _CHANGENAMEDLG_H_
#define _CHANGENAMEDLG_H_


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
#define ID_CHANGENAMEDLG 10000
#define wxID_CHANGE_NAME_TOP 10021
#define ID_CHANGENAME_NEWNAME 10001
#define SYMBOL_CHANGENAMEDLG_STYLE wxCAPTION|wxRESIZE_BORDER|wxSYSTEM_MENU|wxCLOSE_BOX|wxTAB_TRAVERSAL
#define SYMBOL_CHANGENAMEDLG_TITLE _("Change Name")
#define SYMBOL_CHANGENAMEDLG_IDNAME ID_CHANGENAMEDLG
#define SYMBOL_CHANGENAMEDLG_SIZE wxSize(400, 300)
#define SYMBOL_CHANGENAMEDLG_POSITION wxDefaultPosition
////@end control identifiers


/*!
 * ChangeNameDlg class declaration
 */

class ChangeNameDlg: public wxDialog
{    
    DECLARE_DYNAMIC_CLASS( ChangeNameDlg )
    DECLARE_EVENT_TABLE()

public:
    /// Constructors
    ChangeNameDlg();
    ChangeNameDlg( wxWindow* parent, wxWindowID id = SYMBOL_CHANGENAMEDLG_IDNAME, const wxString& caption = SYMBOL_CHANGENAMEDLG_TITLE, const wxPoint& pos = SYMBOL_CHANGENAMEDLG_POSITION, const wxSize& size = SYMBOL_CHANGENAMEDLG_SIZE, long style = SYMBOL_CHANGENAMEDLG_STYLE );

    /// Creation
    bool Create( wxWindow* parent, wxWindowID id = SYMBOL_CHANGENAMEDLG_IDNAME, const wxString& caption = SYMBOL_CHANGENAMEDLG_TITLE, const wxPoint& pos = SYMBOL_CHANGENAMEDLG_POSITION, const wxSize& size = SYMBOL_CHANGENAMEDLG_SIZE, long style = SYMBOL_CHANGENAMEDLG_STYLE );

    /// Destructor
    ~ChangeNameDlg();

    /// Initialises member variables
    void Init();

    /// Creates the controls and sizers
    void CreateControls();

////@begin ChangeNameDlg event handler declarations

    /// wxEVT_COMMAND_TEXT_UPDATED event handler for ID_CHANGENAME_NEWNAME
    void OnChangenameNewnameTextUpdated( wxCommandEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_HELP
    void OnHelpClick( wxCommandEvent& event );

////@end ChangeNameDlg event handler declarations

////@begin ChangeNameDlg member function declarations

    /// Retrieves bitmap resources
    wxBitmap GetBitmapResource( const wxString& name );

    /// Retrieves icon resources
    wxIcon GetIconResource( const wxString& name );
////@end ChangeNameDlg member function declarations

    /// Should we show tooltips?
    static bool ShowToolTips();

////@begin ChangeNameDlg member variables
    wxStaticText* lblDescription;
    wxStaticText* lblCurrentName;
    wxTextCtrl* edtNewName;
    wxButton* btnOk;
////@end ChangeNameDlg member variables
	uint32_t helpId;

	void SetDescription(const tscrypto::tsCryptoString& setTo);
	void SetOldName(const tscrypto::tsCryptoString& setTo);
	void SetNewName(const tscrypto::tsCryptoString& setTo);
	tscrypto::tsCryptoString GetNewName() const;
};

#endif
    // _CHANGENAMEDLG_H_
