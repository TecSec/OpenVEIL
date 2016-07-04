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

#include <windows.h>
#include "stdio.h"
#include "string.h"
#include "stdlib.h"

#ifdef __GNUC__
#define strcpy_s(a,b,c) strcpy(a,c)
#endif

//#define PARAMFLAG_NONE  ( 0 )
//#define PARAMFLAG_FIN   ( 0x1 )
//#define PARAMFLAG_FOUT  ( 0x2 )
//#define PARAMFLAG_FLCID ( 0x4 )
//#define PARAMFLAG_FRETVAL   ( 0x8 )
//#define PARAMFLAG_FOPT  ( 0x10 )
//#define PARAMFLAG_FHASDEFAULT   ( 0x20 )

//#define IDLFLAG_NONE    ( PARAMFLAG_NONE )
//#define IDLFLAG_FIN ( PARAMFLAG_FIN )
//#define IDLFLAG_FOUT    ( PARAMFLAG_FOUT )
//#define IDLFLAG_FLCID   ( PARAMFLAG_FLCID )
//#define IDLFLAG_FRETVAL ( PARAMFLAG_FRETVAL )

const char *LibName = NULL;
bool NameSpaceEnabled = false;
bool OnlyCreateInstance = false;
char DllName[261] = {0,};


void DumpEnum(ITypeInfo *ti, TYPEATTR *ta, bool ForTypedef, bool forFunctionPrototype);

LPCTSTR ToStr (BSTR val)
{
    int i, count = 0;
    {
        wchar_t *p = val;
        while (val != NULL && *p != 0)
        {
            count++;
            p++;
        }
        if (val != NULL)
            count++;
    }
    LPTSTR buff = new char[count+1];

    if (val == NULL)
        buff[0] = 0;
    else
    {
        for (i = 0; i < count; i++)
        {
            buff[i] = (char)val[i];
        }
    }
    return buff;
}

BSTR ToBstr (LPCTSTR val)
{
    int i, count = strlen (val);
    BSTR buff = SysAllocStringLen (NULL, count+1);

    for (i = 0; i <= count; i++)
    {
        buff[i] = val[i];
    }
    return buff;
}

void PutIID(const char *prefix, const char *name, IID iid)
{
    printf ("#if !defined(__%s_%s__type)\n#define __%s_%s__type\n", prefix, name, prefix, name);
    printf ("//{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}\n", iid.Data1, iid.Data2, iid.Data3, iid.Data4[0],
        iid.Data4[1], iid.Data4[2], iid.Data4[3], iid.Data4[4], iid.Data4[5], iid.Data4[6], iid.Data4[7]);
    printf ("TLB_DEFINE_GUID(%s_%s,0x%08lX,0x%04X,0x%04X,0x%02X,0x%02X,0x%02X,0x%02X,0x%02X,0x%02X,0x%02X,0x%02X);\n", prefix,
        name, iid.Data1, iid.Data2, iid.Data3, iid.Data4[0], iid.Data4[1], iid.Data4[2], iid.Data4[3], iid.Data4[4],
        iid.Data4[5], iid.Data4[6], iid.Data4[7]);
    printf ("#endif\n");
}

void Separate ()
{
    printf ("//----------------------------------------------------------------------\n");
}

void DumpTypeDesc (TYPEDESC *td, ITypeInfo *ti, bool forFunctionPrototype, char *postfix)
{
    ITypeInfo *ti1;
    BSTR name = NULL;

    if ( !OnlyCreateInstance )
    {
        switch (td->vt)
        {
            case VT_SAFEARRAY :
                printf ("SAFEARRAY *");
                break;
            case VT_PTR :
    //            printf ("pointer");
                DumpTypeDesc (td->lptdesc, ti, forFunctionPrototype, postfix);
                printf ("*");
                break;
            case VT_EMPTY:
                printf ("/*empty*/ ");
                break;
            case VT_NULL:
                printf ("NULL ");
                break;
            case VT_I2:
                printf ("short ");
                break;
            case VT_I4:
                printf ("long ");
                break;
            case VT_R4:
                printf ("float ");
                break;
            case VT_R8:
                printf ("double ");
                break;
            case VT_CY:
                printf ("CURRENCY ");
                break;
            case VT_DATE:
                printf ("DATE ");
                break;
            case VT_BSTR:
                printf ("BSTR ");
                break;
            case VT_DISPATCH:
                printf ("LPDISPATCH ");
                break;
            case VT_ERROR:
                printf ("SCODE ");
                break;
            case VT_BOOL:
                printf ("VARIANT_BOOL ");
                break;
            case VT_VARIANT:
                printf ("VARIANT ");
                break;
            case VT_UNKNOWN:
                printf ("LPUNKNOWN ");
                break;
            case VT_I1:
                printf ("char ");
                break;
            case VT_UI1:
                printf ("BYTE ");
                break;
            case VT_UI2:
                printf ("WORD ");
                break;
            case VT_UI4:
                printf ("DWORD ");
                break;
            case VT_I8:
                printf ("__int64 ");
                break;
            case VT_UI8:
                printf ("unsigned __int64 ");
                break;
            case VT_INT:
                printf ("int ");
                break;
            case VT_UINT:
                printf ("UINT ");
                break;
            case VT_VOID:
                printf ("void ");
                break;
            case VT_HRESULT:
                printf ("HRESULT ");
                break;
            case VT_CARRAY:
                if (td->lptdesc != nullptr)
                    DumpTypeDesc(td->lptdesc, ti, forFunctionPrototype, postfix);
                
                if (td->lpadesc != nullptr)
                {
                    for (int i = 0; i < td->lpadesc->cDims; i++)
                    {
                        char buff[15];

                        sprintf (buff, "[%d]", td->lpadesc->rgbounds[i].cElements);
                        strcat(postfix, buff);
                    }
                }
                break;
            case VT_USERDEFINED:
                if (SUCCEEDED(ti->GetRefTypeInfo (td->hreftype, &ti1)))
                {
                    TYPEATTR *ta = NULL;

                    if (SUCCEEDED(ti1->GetTypeAttr(&ta)))
                    {
                        if ( ta->typekind == TKIND_ENUM )
                        {
                            DumpEnum(ti1, ta, true, forFunctionPrototype);
                            ti1->Release();
                            return ;
                        }
                    }
                    
                    ITypeLib *container = NULL;
                    UINT index;
                    const char *prefix = NULL;

                    if (ta->typekind == TKIND_INTERFACE || ta->typekind == TKIND_COCLASS || ta->typekind == TKIND_DISPATCH || ta->typekind == TKIND_RECORD || ta->typekind == TKIND_UNION)
                    {
                        if (SUCCEEDED(ti1->GetContainingTypeLib(&container, &index)))
                        {
                            BSTR name = NULL;
                            BSTR docString = NULL;
                            ULONG context;
                            BSTR helpFile = NULL;

                            if (FAILED(container->GetDocumentation (MEMBERID_NIL, &name,
                                    &docString, &context, &helpFile)))
                            {
                                return;
                            }
                            container->Release();
                            container = NULL;
                            prefix = ToStr(name);
                            if (strcmp(prefix, LibName) == 0 /*|| strcmp(prefix, "stdole") == 0*/)
                            {
                                delete prefix;
                                prefix = NULL;
                            }
                        }
                        if (ta->typekind == TKIND_COCLASS)
                        {
                            name = nullptr;

                            if (ta->cImplTypes > 0)
                            {
                                for (int i = 0; name == nullptr && i < ta->cImplTypes; i++)
                                {
                                    ITypeInfo *ti2;
                                    HREFTYPE ref;
                                    TYPEATTR *ta2;

                                    if (SUCCEEDED(ti1->GetRefTypeOfImplType (i, &ref)))
                                    {
                                        if (SUCCEEDED(ti1->GetRefTypeInfo (ref, &ti2)))
                                        {
                                            if (SUCCEEDED(ti2->GetTypeAttr(&ta2)))
                                            {
                                                if ((ta2->wTypeFlags & (TYPEFLAG_FDUAL)) == TYPEFLAG_FDUAL)
                                                {
                                                    ti2->GetDocumentation (MEMBERID_NIL, &name, nullptr, nullptr, nullptr);
                                                }
                                                ti2->ReleaseTypeAttr(ta2);
                                            }
                                            ti2->Release();
                                        }
                                    }
                                }
                            }

                            if (name == nullptr)
                            {
                                if (SUCCEEDED(ti1->GetDocumentation (MEMBERID_NIL, &name,
                                        NULL, NULL, NULL)))
                                {
                                    const char *p;

                                    p = ToStr (name);
                                    if (prefix != NULL)
                                    {
                                        printf ("struct %s::%s ", prefix, p);
                                        delete prefix;
                                        prefix = NULL;
                                    }
                                    else
                                    {
                                        printf ("struct %s ", p);
                                    }
                                    delete [] (void*)p;
                                    SysFreeString (name);
                                }
                            }
                            else
                            {
                                const char *p;

                                p = ToStr (name);
                                if (prefix != NULL)
                                {
                                    printf ("struct %s::%s ", prefix, p);
                                    delete prefix;
                                    prefix = NULL;
                                }
                                else
                                {
                                    printf ("struct %s ", p);
                                }
                                delete [] (void*)p;
                                SysFreeString (name);
                            }
                        }
                        else
                        {
                            if (SUCCEEDED(ti1->GetDocumentation (MEMBERID_NIL, &name,
                                    NULL, NULL, NULL)))
                            {
                                const char *p;

                                p = ToStr (name);
                                if (prefix != NULL)
                                {
                                    printf ("struct %s::%s ", prefix, p);
                                    delete prefix;
                                    prefix = NULL;
                                }
                                else
                                {
                                    printf ("struct %s ", p);
                                }
                                delete [] (void*)p;
                                SysFreeString (name);
                            }
                        }
                    }
                    else
                    {
                        if (SUCCEEDED(ti1->GetDocumentation (MEMBERID_NIL, &name,
                                NULL, NULL, NULL)))
                        {
							if (SUCCEEDED(ti1->GetContainingTypeLib(&container, &index)))
							{
								BSTR name = NULL;
								BSTR docString = NULL;
								ULONG context;
								BSTR helpFile = NULL;

								if (FAILED(container->GetDocumentation (MEMBERID_NIL, &name,
										&docString, &context, &helpFile)))
								{
									return;
								}
								container->Release();
								container = NULL;
								prefix = ToStr(name);
								if (strcmp(prefix, LibName) == 0 /*|| strcmp(prefix, "stdole") == 0*/)
								{
									delete prefix;
									prefix = NULL;
								}
							}

							const char *p;

                            p = ToStr (name);

                            if (prefix != NULL)
                            {
                                printf ("%s::%s ", prefix, p);
                                delete prefix;
                                prefix = NULL;
                            }
                            else
                            {
                                printf ("%s ", p);
                            }
                            delete [] (void*)p;
							SysFreeString (name);
                        }
                    }
                    ti1->Release();
                }
                break;
            case VT_LPSTR:
                printf ("char * ");
                break;
            case VT_LPWSTR:
                printf ("wchar_t * ");
                break;
            case VT_FILETIME:
                printf ("FILETIME ");
                break;
            case VT_BLOB:
                printf ("BLOB ");
                break;
            case VT_STREAM:
                printf ("IStream * ");
                break;
            case VT_STORAGE:
                printf ("IStorage * ");
                break;
            case VT_STREAMED_OBJECT:
                printf ("/* streamed obj*/ IStream * ");
                break;
            case VT_STORED_OBJECT:
                printf ("/* stored obj*/ IStorage * ");
                break;
            case VT_BLOB_OBJECT:
                printf ("/* blob object*/ BLOB ");
                break;
            case VT_CF:
                printf ("/*clipboard format*/ ");
                break;
            case VT_CLSID:
                printf ("GUID ");
                break;
            default:
                printf ("unknown(%d) ", td->vt);
                break;
        }
    }
}

LPCTSTR VariantToStr (VARIANT *v)
{
    VARIANT v1;
    const char *p;

    VariantInit (&v1);
    if (FAILED(VariantChangeType (&v1, v, 0, VT_BSTR)))
        return _strdup("");
    p = ToStr (v1.bstrVal);
    VariantClear (&v1);
    return p;
}

LPCTSTR VariantToStrUnsigned (VARIANT *v)
{
    VARIANT v1;
    const char *p;
    char buff[50];

    VariantInit (&v1);
    if (FAILED(VariantChangeType (&v1, v, 0, VT_UI4)))
        return _strdup("");
    wsprintf(buff, "0x%08lX", v1.lVal);
    p = _strdup(buff);
    VariantClear (&v1);
    return p;
}

void DumpInterfacePredecl(ITypeInfo *ti, TYPEATTR *ta)
{
    BSTR name = NULL;
    BSTR docString = NULL;
    ULONG context;
    BSTR helpFile = NULL;
    const char *ClassName;

    if ( !OnlyCreateInstance )
    {
        if (FAILED(ti->GetDocumentation (MEMBERID_NIL, &name,
                &docString, &context, &helpFile)))
        {
            return;
        }
        {
            ClassName = ToStr(name);
            if (NameSpaceEnabled)
            {
                printf("#if !defined(__%s_%s_FWD_DEFINED__)\n#define __%s_%s_FWD_DEFINED__\nstruct  %s;\n#endif\n\n", LibName, ClassName, LibName, ClassName, ClassName);
            }
            else
            {
                printf("#if !defined(__%s_FWD_DEFINED__)\n#define __%s_FWD_DEFINED__\nstruct  %s;\n#endif\n\n", ClassName, ClassName, ClassName);
            }
            delete [] (void*)ClassName;
            SysFreeString (name);
            SysFreeString (docString);
            SysFreeString (helpFile);
        }
    }
}

void DumpAlias(ITypeInfo *ti, TYPEATTR *ta)
{
    BSTR name = NULL;
    BSTR docString = NULL;
    ULONG context;
    BSTR helpFile = NULL;
    const char *ClassName;
    char postfix[100] = {0,};

    if ( !OnlyCreateInstance )
    {
        if (FAILED(ti->GetDocumentation (MEMBERID_NIL, &name,
                &docString, &context, &helpFile)))
        {
            return;
        }
        {
            ClassName = ToStr(name);
            printf ("#if !defined(__%s__typedef)\n#define __%s__typedef\n", ClassName, ClassName);
            printf ("\ntypedef ");




            DumpTypeDesc (&ta->tdescAlias, ti, false, postfix);
            printf (" %s%s;\n#endif\n", ClassName, postfix);
            delete [] (void*)ClassName;
            SysFreeString (name);
            SysFreeString (docString);
            SysFreeString (helpFile);
        }
    }
}

void DumpEnum(ITypeInfo *ti, TYPEATTR *ta, bool ForTypedef, bool forFunctionPrototype)
{
    BSTR name = NULL;
    BSTR docString = NULL;
    ULONG context;
    BSTR helpFile = NULL;
    int i;
    VARDESC *vd;
    const char *ClassName;

    if ( !OnlyCreateInstance )
    {
        if (FAILED(ti->GetDocumentation (MEMBERID_NIL, &name,
                &docString, &context, &helpFile)))
        {
            return;
        }
        {
            ClassName = ToStr(name);

			ITypeLib *container = NULL;
            UINT index;
            const char *prefix = NULL;

            if (SUCCEEDED(ti->GetContainingTypeLib(&container, &index)))
            {
                BSTR name = NULL;
                BSTR docString = NULL;
                ULONG context;
                BSTR helpFile = NULL;

                if (FAILED(container->GetDocumentation (MEMBERID_NIL, &name,
                        &docString, &context, &helpFile)))
                {
                    return;
                }
                container->Release();
                container = NULL;
                prefix = ToStr(name);
                if (strcmp(prefix, LibName) == 0 /*|| strcmp(prefix, "stdole") == 0*/)
                {
                    delete prefix;
                    prefix = NULL;
                }
				SysFreeString(name);
				SysFreeString(docString);
				SysFreeString(helpFile);
            }


            if ( !ForTypedef && !forFunctionPrototype && strncmp(ClassName, "__MIDL", 6) == 0 )
            {
				if (prefix != nullptr)
					delete prefix;
				prefix = nullptr;
                delete [] (void*)ClassName;
                return ;
            }
            if ( !ForTypedef && !forFunctionPrototype )
            {
                printf ("\n");
                Separate();
				if (NameSpaceEnabled)
					printf ("#if !defined(__%s_%s__enum)\n#define __%s_%s__enum\n", LibName, ClassName, LibName, ClassName);
				else
					printf ("#if !defined(__%s__enum)\n#define __%s__enum\n", ClassName, ClassName);
                printf ("typedef enum {\n");
            }
            else if ( forFunctionPrototype )
            {
				if (prefix != nullptr)
					printf ("%s::%s ", prefix, ClassName);
				else
					printf ("%s ", ClassName);
            }
            else
            {
                printf ("enum {\n");
            }
			if (prefix != nullptr)
				delete prefix;
			prefix = nullptr;
            SysFreeString (name);
            SysFreeString (docString);
            SysFreeString (helpFile);
        }
        if ( !forFunctionPrototype )
        {
            for (i = 0; i < ta->cVars; i++)
            {
                if (SUCCEEDED(ti->GetVarDesc(i, &vd)))
                {
                    BSTR name;
                    UINT count;

                    ti->GetNames (vd->memid, &name, 1, &count);
                    const char *p = ToStr(name);
                    const char *p1 = nullptr;

                    if (strcmp("emptyenum", p) != 0)
                        printf ("    %c%s = %s\n", (i > 0 ? ',' : ' '), p, p1 = VariantToStrUnsigned (vd->lpvarValue));

                    delete [] (void*)p;
                    delete [] (void*)p1;

                    SysFreeString (name);
                    ti->ReleaseVarDesc (vd);
                }
            }
            if ( !ForTypedef  )
            {
                printf ("} %s;\n#endif\n", ClassName);
            }
            else
                printf ("} ");
        }
        delete [] (void*)ClassName;
    }
}

void DumpRecord(ITypeInfo *ti, TYPEATTR *ta)
{
    BSTR name = NULL;
    BSTR docString = NULL;
    ULONG context;
    BSTR helpFile = NULL;
    int i;
    VARDESC *vd;
    const char *ClassName;

    if ( !OnlyCreateInstance )
    {
        if (FAILED(ti->GetDocumentation (MEMBERID_NIL, &name,
                &docString, &context, &helpFile)))
        {
            return;
        }
        ClassName = ToStr(name);
        {
            printf ("\n");
            Separate();
			printf ("#ifndef %s_DEFINED\n#define %s_DEFINED\ntypedef struct tag%s {\n", ClassName, ClassName, ClassName);

            SysFreeString (name);
            SysFreeString (docString);
            SysFreeString (helpFile);
        }
        for (i = 0; i < ta->cVars; i++)
        {
            if (SUCCEEDED(ti->GetVarDesc(i, &vd)))
            {
                BSTR name;
                UINT count;
                char postfix[100] = {0,};

                ti->GetNames (vd->memid, &name, 1, &count);
                const char *p = ToStr(name);
                const char *p1 = nullptr;

                DumpTypeDesc(&vd->elemdescVar.tdesc, ti, true, postfix);
                printf("    %s%s;\n", p, postfix);

                delete [] (void*)p;
                delete [] (void*)p1;

                SysFreeString (name);
                ti->ReleaseVarDesc (vd);
            }
        }
		printf ("} %s;\n#endif // %s_DEFINED\n", ClassName, ClassName);
        delete [] (void*)ClassName;
    }
}

void DumpUnion(ITypeInfo *ti, TYPEATTR *ta)
{
    BSTR name = NULL;
    BSTR docString = NULL;
    ULONG context;
    BSTR helpFile = NULL;
    int i;
    VARDESC *vd;
    const char *ClassName;

    if ( !OnlyCreateInstance )
    {
        if (FAILED(ti->GetDocumentation (MEMBERID_NIL, &name,
                &docString, &context, &helpFile)))
        {
            return;
        }
        ClassName = ToStr(name);
        {
            printf ("\n");
            Separate();
            printf ("typedef union tag%s {\n", ClassName);

            SysFreeString (name);
            SysFreeString (docString);
            SysFreeString (helpFile);
        }
        for (i = 0; i < ta->cVars; i++)
        {
            if (SUCCEEDED(ti->GetVarDesc(i, &vd)))
            {
                BSTR name;
                UINT count;
                char postfix[100] = {0,};

                ti->GetNames (vd->memid, &name, 1, &count);
                const char *p = ToStr(name);
                const char *p1 = nullptr;

                DumpTypeDesc(&vd->elemdescVar.tdesc, ti, true, postfix);
                printf("    %s%s;\n", p, postfix);

                delete [] (void*)p;
                delete [] (void*)p1;

                SysFreeString (name);
                ti->ReleaseVarDesc (vd);
            }
        }
        printf ("} %s;\n", ClassName);
        delete [] (void*)ClassName;
    }
}

void DumpModule(ITypeInfo * /*ti*/, TYPEATTR * /*ta*/)
{
}

void DumpInterfaceFunction (ITypeInfo *ti, TYPEATTR *ta, FUNCDESC *fd, bool IsInterface, const char *ClassName)
{
    UNREFERENCED_PARAMETER(ta);

    char funcName[MAX_PATH] = "";
    BSTR name = NULL;
    BSTR docString = NULL;
    ULONG context;
    BSTR helpFile = NULL;
    int i;
    const char *prefix = "";
    const char *kind = "";
    const char *pure = "";
    const char *convention = "";
    bool IsPut = false;

    if ( !OnlyCreateInstance )
    {
        if (IsInterface)
        {
            switch (fd->callconv)
            {
            case CC_FASTCALL:
                convention = "__fastcall ";
                break;
            case CC_CDECL:
                convention = "__cdecl ";
                break;
            case CC_MSCPASCAL:
                convention = "__pascal ";
                break;
            case CC_MACPASCAL:
                convention = "__pascal ";
                break;
            case CC_STDCALL:
                convention = "__stdcall ";
                break;
            case CC_FPFASTCALL:
                convention = "__fpfastcall ";
                break;
            case CC_SYSCALL:
                convention = "__syscall ";
                break;
            case CC_MPWCDECL:
                convention = "__fastcall ";
                break;
            case CC_MPWPASCAL:
                convention = "__cdecl ";
                break;
            }
            switch (fd->funckind)
            {
            case FUNC_VIRTUAL:
                kind = "virtual ";
                break;
            case FUNC_PUREVIRTUAL:
                kind = "virtual ";
                pure = "PURE";
                break;
            case FUNC_NONVIRTUAL:
                break;
            case FUNC_STATIC:
                kind = "static ";
                break;
            case FUNC_DISPATCH:
                kind = "// virtual ";
                pure = "PURE";
                break;
            }
            switch (fd->invkind)
            {
                case INVOKE_PROPERTYGET:
                    prefix = "get_";
                    break;
                case INVOKE_PROPERTYPUT:
                    prefix = "put_";
                    break;
                case INVOKE_PROPERTYPUTREF:
                    prefix = "putref_";
                    break;
            }
        }
        if (SUCCEEDED(ti->GetDocumentation (fd->memid, &name, &docString, &context, &helpFile)))
        {
            const char *p1, *doc;
            char postfix[100] = {0,};
            p1 = ToStr(name);
            doc = ToStr(docString);

            if (doc != nullptr && doc[0] != 0)
                printf ("/// \\brief %s\n", doc);

            printf ("    %s", kind);
            DumpTypeDesc(&fd->elemdescFunc.tdesc, ti, true, postfix);
            printf ("%s%s%s%s(", convention, prefix, p1, postfix);
            strcpy_s(funcName, sizeof(funcName), p1);

            delete [] (void*)doc;
            delete [] (void*)p1;
            SysFreeString (name);
            SysFreeString (docString);
            SysFreeString (helpFile);
        }

        BSTR *names = new BSTR[fd->cParams + 1];
        UINT count;
        memset (names, 0, sizeof(BSTR *) * (fd->cParams + 1));
        ti->GetNames (fd->memid, names, fd->cParams + 1, &count);


        for (i = 0; i < fd->cParams; i++)
        {
            const char *p;
            char postfix[100] = {0,};
            if (names[i+1])
                p = ToStr (names[i+1]);
            else
                p = strdup("Value");

            if ( i > 0 )
            {
                printf(",");
            }
            DumpTypeDesc (&fd->lprgelemdescParam[i].tdesc, ti, true, postfix);
            printf (" %s%s", p, postfix);
            delete [] (void*)p;

            if (i+1 < (int)count)
                SysFreeString (names[i+1]);
        }
        SysFreeString (names[0]);
        delete [] names;

        printf (") %s;\n", pure);
        if (IsInterface)
        {
            if (fd->funckind == FUNC_DISPATCH)
            {
                printf ("#define DISPID_%s_%s 0x%08X\n", ClassName, funcName, fd->memid);
            }
        }
    }
}

void DumpInterface(ITypeInfo *ti, TYPEATTR *ta)
{
    BSTR name = NULL;
    BSTR docString = NULL;
    ULONG context;
    BSTR helpFile = NULL;
    int i;
    ITypeInfo * ti2 = NULL;
    HREFTYPE ref;
    TYPEATTR *ta2;
    FUNCDESC *fd;
    const char *ClassName;
    const char *doc;

    if ( !OnlyCreateInstance )
    {
        if (FAILED(ti->GetDocumentation (MEMBERID_NIL, &name,
                &docString, &context, &helpFile)))
        {
            return;
        }

        {
            ClassName = ToStr(name);
            doc = ToStr(docString);
            printf ("\n");
            Separate();

            if (NameSpaceEnabled)
            {
                printf ("#if !defined(__%s_%s_INTERFACE_DEFINED__)\n#define __%s_%s_INTERFACE_DEFINED__\n", LibName, ClassName, LibName, ClassName);
            }
            else
            {
                printf ("#if !defined(__%s_INTERFACE_DEFINED__)\n#define __%s_INTERFACE_DEFINED__\n", ClassName, ClassName);
            }
            if (doc != nullptr && doc[0] != 0)
                printf ("/// \\brief %s\n", doc);
            printf ("#if (_MSC_VER > 1100)\n");
            printf ("struct DECLSPEC_UUID(\"%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X\") DECLSPEC_NOVTABLE\n",
                ta->guid.Data1, ta->guid.Data2, ta->guid.Data3, ta->guid.Data4[0], ta->guid.Data4[1], ta->guid.Data4[2],
                ta->guid.Data4[3], ta->guid.Data4[4], ta->guid.Data4[5], ta->guid.Data4[6], ta->guid.Data4[7]);
            printf ("#else\n");
            printf ("struct\n");
            printf ("#endif\n");
            printf ("%s ", ClassName);
            SysFreeString (name);
            SysFreeString (docString);
            SysFreeString (helpFile);
        }

        if (ta->typekind == TKIND_COCLASS)
        {
            if (ta->cImplTypes > 0)
            {
                printf (";\n");
                for (i = 0; i < ta->cImplTypes; i++)
                {
                    if (SUCCEEDED(ti->GetRefTypeOfImplType (i, &ref)))
                    {
                        if (SUCCEEDED(ti->GetRefTypeInfo (ref, &ti2)))
                        {
                            if (FAILED(ti2->GetDocumentation (MEMBERID_NIL, &name,
                                &docString, &context, &helpFile)))
                            {
                                return;
                            }
                            ITypeLib *container = NULL;
                            UINT index;
                            const char *prefix = NULL;

                            if (SUCCEEDED(ti2->GetContainingTypeLib(&container, &index)))
                            {
                                BSTR name = NULL;
                                BSTR docString = NULL;
                                ULONG context;
                                BSTR helpFile = NULL;

                                if (FAILED(container->GetDocumentation (MEMBERID_NIL, &name,
                                        &docString, &context, &helpFile)))
                                {
                                    return;
                                }
                                container->Release();
                                container = NULL;
                                prefix = ToStr(name);
                                if (strcmp(prefix, LibName) == 0 /*|| strcmp(prefix, "stdole") == 0*/)
                                {
                                    delete prefix;
                                    prefix = NULL;
                                }
                            }

                            if (SUCCEEDED(ti2->GetTypeAttr(&ta2)))
                            {
            //TYPEFLAG_FAPPOBJECT
            //TYPEFLAG_FCANCREATE
            //TYPEFLAG_FLICENSED
            //TYPEFLAG_FPREDECLID
            //TYPEFLAG_FHIDDEN
            //TYPEFLAG_FCONTROL
            //TYPEFLAG_FDUAL
            //TYPEFLAG_FNONEXTENSIBLE
            //TYPEFLAG_FOLEAUTOMATION
            //TYPEFLAG_FRESTRICTED
            //TYPEFLAG_FAGGREGATABLE
            //TYPEFLAG_FREPLACEABLE
            //TYPEFLAG_FDISPATCHABLE
            //TYPEFLAG_FREVERSEBIND
                                printf ("    // public ");
                                ti2->ReleaseTypeAttr(ta2);
                            }
                            else
                                printf ("    // public ");
                            {
                                const char *p1;
                                p1 = ToStr(name);
                                if (prefix != NULL)
                                {
                                    printf ("%s::", prefix);
                                    delete prefix;
                                    prefix = NULL;
                                }
                                printf ("%s\n", p1);
                                delete [] (void *)p1;
                                SysFreeString (name);
                                SysFreeString (docString);
                                SysFreeString (helpFile);
                            }
                            ti2->Release();
                        }
                    }
                }
            }
            printf ("#endif\n");
        }
        else
        {
            if (ta->cImplTypes > 0)
            {
                printf (": ");
                for (i = 0; i < ta->cImplTypes; i++)
                {
                    if (SUCCEEDED(ti->GetRefTypeOfImplType (i, &ref)))
                    {
                        if (SUCCEEDED(ti->GetRefTypeInfo (ref, &ti2)))
                        {
                            if (FAILED(ti2->GetDocumentation (MEMBERID_NIL, &name,
                                &docString, &context, &helpFile)))
                            {
                                return;
                            }
                            ITypeLib *container = NULL;
                            UINT index;
                            const char *prefix = NULL;

                            if (SUCCEEDED(ti2->GetContainingTypeLib(&container, &index)))
                            {
                                BSTR name = NULL;
                                BSTR docString = NULL;
                                ULONG context;
                                BSTR helpFile = NULL;

                                if (FAILED(container->GetDocumentation (MEMBERID_NIL, &name,
                                        &docString, &context, &helpFile)))
                                {
                                    return;
                                }
                                container->Release();
                                container = NULL;
                                prefix = ToStr(name);
                                if (strcmp(prefix, LibName) == 0 /*|| strcmp(prefix, "stdole") == 0*/)
                                {
                                    delete prefix;
                                    prefix = NULL;
                                }
                            }

                            if (SUCCEEDED(ti2->GetTypeAttr(&ta2)))
                            {
            //TYPEFLAG_FAPPOBJECT
            //TYPEFLAG_FCANCREATE
            //TYPEFLAG_FLICENSED
            //TYPEFLAG_FPREDECLID
            //TYPEFLAG_FHIDDEN
            //TYPEFLAG_FCONTROL
            //TYPEFLAG_FDUAL
            //TYPEFLAG_FNONEXTENSIBLE
            //TYPEFLAG_FOLEAUTOMATION
            //TYPEFLAG_FRESTRICTED
            //TYPEFLAG_FAGGREGATABLE
            //TYPEFLAG_FREPLACEABLE
            //TYPEFLAG_FDISPATCHABLE
            //TYPEFLAG_FREVERSEBIND
                                printf ("%cpublic ", (i > 0) ? ',' : ' ');
                                ti2->ReleaseTypeAttr(ta2);
                            }
                            else
                                printf ("%cpublic ", (i > 0) ? ',' : ' ');
                            {
                                const char *p1;
                                p1 = ToStr(name);
                                if (prefix != NULL)
                                {
                                    printf ("%s::", prefix);
                                    delete prefix;
                                    prefix = NULL;
                                }
                                printf ("%s", p1);
                                delete [] (void *)p1;
                                SysFreeString (name);
                                SysFreeString (docString);
                                SysFreeString (helpFile);
                            }
                            ti2->Release();
                        }
                    }
                }
            }
            printf ("\n{\npublic:\n");

            for (i = 0; i < ta->cFuncs; i++)
            {
                if (SUCCEEDED(ti->GetFuncDesc(i, &fd)))
                {
                    DumpInterfaceFunction(ti, ta, fd, true, ClassName);
                    ti->ReleaseFuncDesc (fd);
                }
            }
            printf ("protected:\n    %s () {};\n    ~%s () {};\n};\n#endif\n", ClassName, ClassName);
        }
        delete [] (void*)ClassName;
    }
}

void DumpDispatch(ITypeInfo *ti, TYPEATTR *ta)
{
    BSTR name = NULL;
    BSTR docString = NULL;
//    ULONG context;
    BSTR helpFile = NULL;
//    int i;
    ITypeInfo * ti2 = NULL;
    HREFTYPE ref;
    TYPEATTR *ta2;
//    FUNCDESC *fd;
//    VARDESC *vd;
//    const char *ClassName;
//    const char *doc;

    if ( !OnlyCreateInstance )
    {
//        if (ta->wTypeFlags & TYPEFLAG_FDUAL)
        {
            if (SUCCEEDED(ti->GetRefTypeOfImplType (-1, &ref)) &&
                SUCCEEDED(ti->GetRefTypeInfo (ref, &ti2)))
            {
                if (SUCCEEDED(ti2->GetTypeAttr(&ta2)))
                {
                    DumpInterface (ti2, ta2);
                    ti2->ReleaseTypeAttr(ta2);
                }
                ti2->Release();
            }
            else 
            {
                DumpInterface (ti, ta);
            }

            return;
        }
    }
}

void DumpCoClass(ITypeInfo *ti, TYPEATTR *ta)
{
    BSTR name = NULL;
    BSTR docString = NULL;
//    ULONG context;
    BSTR helpFile = NULL;
//    int i;
    ITypeInfo * ti2 = NULL;
    HREFTYPE ref;
    TYPEATTR *ta2;
//    FUNCDESC *fd;
//    VARDESC *vd;
//    const char *ClassName;
//    const char *doc;

    if ( !OnlyCreateInstance )
    {
//        if (ta->wTypeFlags & TYPEFLAG_FDUAL)
        {
            if (SUCCEEDED(ti->GetRefTypeOfImplType (-1, &ref)) &&
                SUCCEEDED(ti->GetRefTypeInfo (ref, &ti2)))
            {
                if (SUCCEEDED(ti2->GetTypeAttr(&ta2)))
                {
                    DumpInterface (ti2, ta2);
                    ti2->ReleaseTypeAttr(ta2);
                }
                ti2->Release();
            }
            else 
            {
                DumpInterface (ti, ta);
            }

            return;
        }
    }
}

void DumpIIDs (ITypeInfo *ti)
{
    TYPEATTR *ta = NULL;
    const char *Name = NULL;

    {
        BSTR name = NULL;
        BSTR docString = NULL;
        ULONG context;
        BSTR helpFile = NULL;

        if (FAILED(ti->GetDocumentation (MEMBERID_NIL, &name,
                &docString, &context, &helpFile)))
        {
            return;
        }
        Name = ToStr(name);
    }
    if (FAILED(ti->GetTypeAttr(&ta)))
    {
    }
    else
    {
        if ( !OnlyCreateInstance )
        {
            switch (ta->typekind)
            {
                case TKIND_ALIAS:
                    break;
                case TKIND_ENUM:
                    break;
                case TKIND_RECORD:
                    break;
                case TKIND_UNION:
                    break;
                case TKIND_MODULE:
                    break;
                case TKIND_INTERFACE:
                    PutIID ("IID", Name, ta->guid);
                    break;
                case TKIND_DISPATCH:
                    if (ta->wTypeFlags & TYPEFLAG_FDUAL)
                        PutIID ("IID", Name, ta->guid);
                    else
                        PutIID ("DIID", Name, ta->guid);
                    break;
                case TKIND_COCLASS:
                    PutIID ("CLSID", Name, ta->guid);
                    break;
            }
        }
        else
        {
            if ( ta->typekind == TKIND_COCLASS )
            {
//				PutIID ("CLSID", Name, ta->guid);
                printf ("#define ts_CLSID_%s \"%s.DLL\",CLSID_%s\n", Name, DllName, Name);
            }
        }
        ti->ReleaseTypeAttr(ta);
    }
    delete [] (void*)Name;
    Name = NULL;
}

void DumpClassInterface (ITypeInfo *ti)
{
    TYPEATTR *ta = NULL;

    if ( !OnlyCreateInstance )
    {
        if (FAILED(ti->GetTypeAttr(&ta)))
        {
        }
        else
        {
            switch (ta->typekind)
            {
                case TKIND_ALIAS:
                    break;
                case TKIND_ENUM:
                    break;
                case TKIND_RECORD:
                    break;
                case TKIND_UNION:
                    break;
                case TKIND_MODULE:
                    DumpModule(ti, ta);
                    break;
                case TKIND_INTERFACE:
                    DumpInterface(ti, ta);
                    break;
                case TKIND_DISPATCH:
                    DumpDispatch(ti, ta);
                    break;
                case TKIND_COCLASS:
                    DumpCoClass(ti, ta);
                    break;
            }
            ti->ReleaseTypeAttr(ta);
        }
    }
}

void DumpDataType (ITypeInfo *ti, bool AllowCoClass)
{
    TYPEATTR *ta = NULL;

    if ( !OnlyCreateInstance )
    {
        if (FAILED(ti->GetTypeAttr(&ta)))
        {
        }
        else
        {
            switch (ta->typekind)
            {
                case TKIND_ALIAS:
                    if (AllowCoClass)
                        DumpAlias(ti, ta);
                    break;
                case TKIND_ENUM:
                    if (!AllowCoClass)
                        DumpEnum(ti, ta, false, false);
                    break;
                case TKIND_RECORD:
                    if (!AllowCoClass)
                        DumpRecord(ti, ta);
                    break;
                case TKIND_UNION:
                    if (!AllowCoClass)
                        DumpUnion(ti, ta);
                    break;
                case TKIND_MODULE:
                    break;
                case TKIND_INTERFACE:
                    if ( !AllowCoClass )
                    {
                        DumpInterfacePredecl(ti, ta);
                    }
                    break;
                case TKIND_DISPATCH:
                    if ( !AllowCoClass )
                    {
                        DumpInterfacePredecl(ti, ta);
                    }
                    break;
                case TKIND_COCLASS:
                    DumpInterfacePredecl(ti, ta);
                    break;
            }
            ti->ReleaseTypeAttr(ta);
        }
    }
}

void PutHeaderBlock (void)
{
    char buff[261];

    if ( !OnlyCreateInstance )
    {
        wsprintf (buff, "__%s_H__", LibName);
    }
    else
    {
        wsprintf (buff, "__%sci_H__", LibName);
    }
    strupr (buff);
    printf ("#if !defined(%s)\n#define  %s\n\n", buff, buff);
}

void PutTrailerBlock (void)
{
    char buff[261];

    printf ("#pragma warning(pop)\n");
    if ( !OnlyCreateInstance )
        wsprintf (buff, "__%s_H__", LibName);
    else
        wsprintf (buff, "__%sci_H__", LibName);
    strupr (buff);
    printf ("#endif // %s\n\n", buff);
}

void DumpLib (ITypeLib *tlb)
{
    TLIBATTR *libAttr;
    BSTR tmp = NULL;
    UINT typeCount;
    UINT i;
    ITypeInfo *ti = NULL;
    char *Kinds[3] = {"Win 16", "Win 32", "Mac"};

    {
        BSTR name = NULL;
        BSTR docString = NULL;
        ULONG context;
        BSTR helpFile = NULL;

        if (FAILED(tlb->GetDocumentation (MEMBERID_NIL, &name,
                &docString, &context, &helpFile)))
        {
            return;
        }
        LibName = ToStr(name);
    }
    PutHeaderBlock();
    if (FAILED(tlb->GetLibAttr (&libAttr)))
    {
        fprintf (stderr,"Unable to get library attributes.\n");
        return;
    }
    printf("#pragma warning(push)\n");
    printf("#pragma warning(disable:4099)\n\n");


    if ( !OnlyCreateInstance )
    {
        PutIID("TID", LibName, libAttr->guid);
        PutIID("LIBID", LibName, libAttr->guid);
    }

    printf ("\n");

    tlb->ReleaseTLibAttr (libAttr);
    typeCount = tlb->GetTypeInfoCount ();
    //
    // Dump out the IID's
    //
    for (i = 0; i < typeCount; i++)
    {
        if (SUCCEEDED(tlb->GetTypeInfo (i, &ti)))
        {
            DumpIIDs (ti);
            ti->Release();
            ti = NULL;
        }
    }
    printf ("\n");
    Separate ();
    if ( NameSpaceEnabled )
    {
        printf("\nnamespace %s {", LibName);
    }

    if ( !OnlyCreateInstance )
    {
        printf ("\n");
        //
        // Now dump out the enums, records, etc.
        //
        for (i = 0; i < typeCount; i++)
        {
            if (SUCCEEDED(tlb->GetTypeInfo (i, &ti)))
            {
                DumpDataType (ti, false);
                ti->Release();
                ti = NULL;
            }
        }
        for (i = 0; i < typeCount; i++)
        {
            if (SUCCEEDED(tlb->GetTypeInfo (i, &ti)))
            {
                DumpDataType (ti, true);
                ti->Release();
                ti = NULL;
            }
        }

        printf ("\n");
        Separate ();
        printf ("\n");
        //
        // Now dump out the VTABLE interfaces
        //
        for (i = 0; i < typeCount; i++)
        {
            if (SUCCEEDED(tlb->GetTypeInfo (i, &ti)))
            {
                DumpClassInterface (ti);
                ti->Release();
                ti = NULL;
            }
        }
        printf ("\n");
        Separate ();
        printf ("\n");
    }

    if ( NameSpaceEnabled )
    {
        printf("\n} // %s\n\n", LibName);
//        printf("using namespace %s;\n", LibName);
    }

    PutTrailerBlock();
}

int main (int argc, const char **argv)
{
    HRESULT res;
    BSTR chars;
    ITypeLib *tlb;
    const char *filename = NULL;
    int i;

    for ( i = 1; i < argc; i++ )
    {
        if ( argv[i][0] == '-' )
        {
            if ( argv[i][1] == 'n' || argv[i][1] == 'N' )
            {
                NameSpaceEnabled = true;
            }
            else if ( argv[i][1] == 'c' || argv[i][1] == 'C' )
            {
                OnlyCreateInstance = true;
            }
            else
            {
                fprintf (stderr, "Com2H [-n(amespace)] [-c(reateinstance)] <filename>\n");
                return 1;
            }
        }
        else if ( filename != NULL )
        {
            fprintf (stderr, "Com2H [-n(amespace)] [-c(reateinstance)] <filename>\n");
            return 1;
        }
        else
            filename = argv[i];
    }

    if ( filename == NULL )
    {
        fprintf (stderr, "Com2H [-n(amespace)] [-c(reateinstance)] <filename>\n");
        return 1;
    }

    OleInitialize(NULL);

    if ( strrchr(filename, '\\') != NULL )
    {
        strcpy (DllName, strrchr(filename, '\\') + 1);
    }
    else
    {
        strcpy (DllName, filename);
    }
    if ( strrchr(DllName, '.') != NULL )
        *strrchr(DllName, '.') = 0;

    if (strnicmp(filename, "Typelib\\{", 9) == 0)
    {
        HKEY key;
        char path[MAX_PATH + 1];
        LONG pathLen = sizeof(path) / sizeof(path[0]);


        if (RegCreateKeyA(HKEY_CLASSES_ROOT, filename, &key) != ERROR_SUCCESS)
        {
            fprintf(stderr, "Unable to load the type library using the specified registry key\n");
            return 1;
        }
        if (RegQueryValueA(key, "", path, &pathLen) != ERROR_SUCCESS)
        {
            RegCloseKey(key);
            fprintf(stderr, "Unable to load the type library using the specified registry key\n");
            return 1;
        }
        chars = ToBstr(path);
    }
    else
    {
        chars = ToBstr(filename);
    }
    // if (FAILED(res = LoadTypeLibEx (chars, REGKIND_NONE, &tlb)))
    // if (FAILED(res = LoadRegTypeLib (chars, &tlb)))
    if (FAILED(res = LoadTypeLib (chars, &tlb)))
    {
        fprintf (stderr, "Load Type Lib failed [%08x] last error = [%ld]\nFilename='%s'", res, GetLastError(), filename);
        SysFreeString (chars);
        OleUninitialize();
        return 1;
    }
    SysFreeString(chars);

    DumpLib (tlb);
    if ( LibName )
    {
        delete [] (void*)LibName;
    }
    LibName = NULL;

    tlb->Release();
    OleUninitialize();
    return 0;
}
