/////////////////////////////////////////////////////////////////////////////
// Name:        guidesignerforapiapp.h
// Purpose:     
// Author:      Roger Butler
// Modified by: 
// Created:     09/02/2016 10:25:55
// RCS-ID:      
// Copyright:   Copyright (c) 2018, TecSec, Inc.  
// Licence:     
/////////////////////////////////////////////////////////////////////////////

#ifndef _GUIDESIGNERFORAPIAPP_H_
#define _GUIDESIGNERFORAPIAPP_H_


/*!
 * Includes
 */

////@begin includes
#include "wx/image.h"
#include "aboutckm.h"
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
////@end control identifiers

/*!
 * GuiDesignerForAPIApp class declaration
 */

class GuiDesignerForAPIApp: public wxApp
{    
    DECLARE_CLASS( GuiDesignerForAPIApp )
    DECLARE_EVENT_TABLE()

public:
    /// Constructor
    GuiDesignerForAPIApp();

    void Init();

    /// Initialises the application
    virtual bool OnInit();

    /// Called on exit
    virtual int OnExit();

////@begin GuiDesignerForAPIApp event handler declarations

////@end GuiDesignerForAPIApp event handler declarations

////@begin GuiDesignerForAPIApp member function declarations

////@end GuiDesignerForAPIApp member function declarations

////@begin GuiDesignerForAPIApp member variables
////@end GuiDesignerForAPIApp member variables
};

/*!
 * Application instance declaration 
 */

////@begin declare app
DECLARE_APP(GuiDesignerForAPIApp)
////@end declare app

#endif
    // _GUIDESIGNERFORAPIAPP_H_
