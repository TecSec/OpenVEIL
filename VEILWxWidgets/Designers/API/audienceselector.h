/////////////////////////////////////////////////////////////////////////////
// Name:        audienceselector.h
// Purpose:     
// Author:      Roger Butler
// Modified by: 
// Created:     09/02/2016 13:05:32
// RCS-ID:      
// Copyright:   Copyright (c) 2017, TecSec, Inc.  
// Licence:     
/////////////////////////////////////////////////////////////////////////////

#ifndef _AUDIENCESELECTOR_H_
#define _AUDIENCESELECTOR_H_


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
#define ID_AUDIENCESELECTOR 10000
#define ID_FAVORITELIST 10001
#define ID_TOKENLIST 10002
#define ID_CGLIST 10003
#define ID_LISTBOX 10004
#define ID_ADD 10005
#define ID_EDIT 10006
#define ID_DELETE 10007
#define ID_CREATE_FAVORITE 10008
#define ID_DELETE_FAVORITE 10009
#define SYMBOL_AUDIENCESELECTOR_STYLE wxCAPTION|wxSYSTEM_MENU|wxCLOSE_BOX|wxTAB_TRAVERSAL
#define SYMBOL_AUDIENCESELECTOR_TITLE _("Audience Selector")
#define SYMBOL_AUDIENCESELECTOR_IDNAME ID_AUDIENCESELECTOR
#define SYMBOL_AUDIENCESELECTOR_SIZE wxSize(400, 350)
#define SYMBOL_AUDIENCESELECTOR_POSITION wxDefaultPosition
////@end control identifiers


/*!
 * AudienceSelector class declaration
 */

class AudienceSelector: public wxDialog
{    
    DECLARE_DYNAMIC_CLASS( AudienceSelector )
    DECLARE_EVENT_TABLE()

public:
    /// Constructors
    AudienceSelector();
    AudienceSelector( wxWindow* parent, wxWindowID id = SYMBOL_AUDIENCESELECTOR_IDNAME, const wxString& caption = SYMBOL_AUDIENCESELECTOR_TITLE, const wxPoint& pos = SYMBOL_AUDIENCESELECTOR_POSITION, const wxSize& size = SYMBOL_AUDIENCESELECTOR_SIZE, long style = SYMBOL_AUDIENCESELECTOR_STYLE );

    /// Creation
    bool Create( wxWindow* parent, wxWindowID id = SYMBOL_AUDIENCESELECTOR_IDNAME, const wxString& caption = SYMBOL_AUDIENCESELECTOR_TITLE, const wxPoint& pos = SYMBOL_AUDIENCESELECTOR_POSITION, const wxSize& size = SYMBOL_AUDIENCESELECTOR_SIZE, long style = SYMBOL_AUDIENCESELECTOR_STYLE );

    /// Destructor
    ~AudienceSelector();

    /// Initialises member variables
    void Init();

    /// Creates the controls and sizers
    void CreateControls();

////@begin AudienceSelector event handler declarations


    /// wxEVT_COMMAND_CHOICE_SELECTED event handler for ID_FAVORITELIST
    void OnFavoritelistSelected( wxCommandEvent& event );

    /// wxEVT_COMMAND_CHOICE_SELECTED event handler for ID_TOKENLIST
    void OnTokenlistSelected( wxCommandEvent& event );

    /// wxEVT_COMMAND_CHOICE_SELECTED event handler for ID_CGLIST
    void OnCglistSelected( wxCommandEvent& event );

    /// wxEVT_COMMAND_LISTBOX_SELECTED event handler for ID_LISTBOX
    void OnListboxSelected( wxCommandEvent& event );

    /// wxEVT_COMMAND_LISTBOX_DOUBLECLICKED event handler for ID_LISTBOX
    void OnListboxDoubleClicked( wxCommandEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_ADD
    void OnAddClick( wxCommandEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_EDIT
    void OnEditClick( wxCommandEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_DELETE
    void OnDeleteClick( wxCommandEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_CREATE_FAVORITE
    void OnCreateFavoriteClick( wxCommandEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_DELETE_FAVORITE
    void OnDeleteFavoriteClick( wxCommandEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_OK
    void OnOkClick( wxCommandEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_CANCEL
    void OnCancelClick( wxCommandEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_HELP
    void OnHelpClick( wxCommandEvent& event );

////@end AudienceSelector event handler declarations

////@begin AudienceSelector member function declarations

    /// Retrieves bitmap resources
    wxBitmap GetBitmapResource( const wxString& name );

    /// Retrieves icon resources
    wxIcon GetIconResource( const wxString& name );
////@end AudienceSelector member function declarations

    /// Should we show tooltips?
    static bool ShowToolTips();

////@begin AudienceSelector member variables
    wxChoice* cmbFavorites;
    wxChoice* cmbTokens;
    wxChoice* cmbCG;
    wxListBox* lstGroups;
    wxButton* btnAdd;
    wxButton* btnEdit;
    wxButton* btnDelete;
    wxButton* btnCreateFavorite;
    wxButton* btnDeleteFavorite;
    wxButton* btnOK;
    wxButton* btnCancel;
    wxButton* btnHelp;
////@end AudienceSelector member variables
};

#endif
    // _AUDIENCESELECTOR_H_
