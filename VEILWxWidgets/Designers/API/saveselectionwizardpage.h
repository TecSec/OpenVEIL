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

#ifndef _SAVESELECTIONWIZARDPAGE_H_
#define _SAVESELECTIONWIZARDPAGE_H_


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
class SaveSelectionWizardPage;
////@end forward declarations

/*!
 * Control identifiers
 */

////@begin control identifiers
#define ID_SAVE_FAVORITE 10004
#define ID_TEXTCTRL1 10013
#define ID_SAVE 10014
////@end control identifiers


/*!
 * SaveSelectionWizardPage class declaration
 */

class SaveSelectionWizardPage: public wxWizardPageSimple, public ISkippablePage
{    
    DECLARE_DYNAMIC_CLASS( SaveSelectionWizardPage )
    DECLARE_EVENT_TABLE()

public:
    /// Constructors
    SaveSelectionWizardPage();

    SaveSelectionWizardPage( wxWizard* parent );

    /// Creation
    bool Create( wxWizard* parent );

    /// Destructor
    ~SaveSelectionWizardPage();

    /// Initialises member variables
    void Init();

    /// Creates the controls and sizers
    void CreateControls();

////@begin SaveSelectionWizardPage event handler declarations

    /// wxEVT_WIZARD_PAGE_CHANGED event handler for ID_SAVE_FAVORITE
    void OnSaveFavoritePageChanged( wxWizardEvent& event );

    /// wxEVT_WIZARD_PAGE_CHANGING event handler for ID_SAVE_FAVORITE
    void OnSaveFavoritePageChanging( wxWizardEvent& event );

    /// wxEVT_WIZARD_FINISHED event handler for ID_SAVE_FAVORITE
    void OnSaveFavoriteFinished( wxWizardEvent& event );

    /// wxEVT_WIZARD_HELP event handler for ID_SAVE_FAVORITE
    void OnSaveFavoriteHelp( wxWizardEvent& event );

    /// wxEVT_COMMAND_TEXT_UPDATED event handler for ID_TEXTCTRL1
    void OnTextctrl1TextUpdated( wxCommandEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_SAVE
    void OnSaveClick( wxCommandEvent& event );

////@end SaveSelectionWizardPage event handler declarations

////@begin SaveSelectionWizardPage member function declarations

    /// Gets the previous page
    virtual wxWizardPage* GetPrev() const;

    /// Gets the next page
    virtual wxWizardPage* GetNext() const;

    /// Retrieves bitmap resources
    wxBitmap GetBitmapResource( const wxString& name );

    /// Retrieves icon resources
    wxIcon GetIconResource( const wxString& name );
////@end SaveSelectionWizardPage member function declarations

    /// Should we show tooltips?
    static bool ShowToolTips();

////@begin SaveSelectionWizardPage member variables
    wxStaticText* _lblOptional;
    wxTextCtrl* _txtFavoriteName;
    wxButton* _btnSave;
////@end SaveSelectionWizardPage member variables
	wxWizardPage* nextPage;
	wxWizardPage* prevPage;
	void SetNextPage(wxWizardPage* setTo) { nextPage = setTo; }
	void SetPrevPage(wxWizardPage* setTo) { prevPage = setTo; }

	void updateControls();

	// Inherited via ISkippablePage
	virtual bool skipMe() override;
};

#endif
    // _SAVESELECTIONWIZARDPAGE_H_
