/////////////////////////////////////////////////////////////////////////////
// Name:        favoriteselectionpage.h
// Purpose:     
// Author:      Roger Butler
// Modified by: 
// Created:     13/02/2017 16:04:06
// RCS-ID:      
// Copyright:   Copyright (c) 2017, TecSec, Inc.  
// Licence:     
/////////////////////////////////////////////////////////////////////////////

#ifndef _FAVORITESELECTIONPAGE_H_
#define _FAVORITESELECTIONPAGE_H_


/*!
 * Includes
 */

////@begin includes
#include "wx/wizard.h"
////@end includes

/*!
 * Forward declarations
 */

////@begin forward declarations
class FavoriteSelectionPage;
////@end forward declarations

/*!
 * Control identifiers
 */

////@begin control identifiers
#define ID_FAVORITE_SELECTION_PAGE 10018
#define ID_CHOICE 10019
////@end control identifiers


/*!
 * FavoriteSelectionPage class declaration
 */

class FavoriteSelectionPage: public wxWizardPage
{    
    DECLARE_DYNAMIC_CLASS( FavoriteSelectionPage )
    DECLARE_EVENT_TABLE()

public:
    /// Constructors
    FavoriteSelectionPage();

    FavoriteSelectionPage( wxWizard* parent );

    /// Creation
    bool Create( wxWizard* parent );

    /// Destructor
    ~FavoriteSelectionPage();

    /// Initialises member variables
    void Init();

    /// Creates the controls and sizers
    void CreateControls();

////@begin FavoriteSelectionPage event handler declarations

    /// wxEVT_WIZARD_PAGE_CHANGED event handler for ID_FAVORITE_SELECTION_PAGE
    void OnFavoriteSelectionPagePageChanged( wxWizardEvent& event );

    /// wxEVT_WIZARD_PAGE_CHANGING event handler for ID_FAVORITE_SELECTION_PAGE
    void OnFavoriteSelectionPagePageChanging( wxWizardEvent& event );

    /// wxEVT_WIZARD_FINISHED event handler for ID_FAVORITE_SELECTION_PAGE
    void OnFavoriteSelectionPageFinished( wxWizardEvent& event );

    /// wxEVT_WIZARD_HELP event handler for ID_FAVORITE_SELECTION_PAGE
    void OnFavoriteSelectionPageHelp( wxWizardEvent& event );

    /// wxEVT_COMMAND_CHOICE_SELECTED event handler for ID_CHOICE
    void OnChoiceSelected( wxCommandEvent& event );

////@end FavoriteSelectionPage event handler declarations

////@begin FavoriteSelectionPage member function declarations

    /// Gets the previous page
    virtual wxWizardPage* GetPrev() const;

    /// Gets the next page
    virtual wxWizardPage* GetNext() const;

    /// Retrieves bitmap resources
    wxBitmap GetBitmapResource( const wxString& name );

    /// Retrieves icon resources
    wxIcon GetIconResource( const wxString& name );
////@end FavoriteSelectionPage member function declarations

    /// Should we show tooltips?
    static bool ShowToolTips();

////@begin FavoriteSelectionPage member variables
    wxChoice* _cmbFavorites;
////@end FavoriteSelectionPage member variables
	wxWizardPage* nextPage;
	wxWizardPage* prevPage;
	void SetNextPage(wxWizardPage* setTo) { nextPage = setTo; }
	void SetPrevPage(wxWizardPage* setTo) { prevPage = setTo; }

};

#endif
    // _FAVORITESELECTIONPAGE_H_
