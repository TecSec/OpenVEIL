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

class FavoriteSelectionPage: public wxWizardPage, public ISkippablePage
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
    virtual wxWizardPage* GetPrev() const override;

    /// Gets the next page
    virtual wxWizardPage* GetNext() const override;

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


	// Inherited via ISkippablePage
	virtual bool skipMe() override;

};

#endif
    // _FAVORITESELECTIONPAGE_H_
