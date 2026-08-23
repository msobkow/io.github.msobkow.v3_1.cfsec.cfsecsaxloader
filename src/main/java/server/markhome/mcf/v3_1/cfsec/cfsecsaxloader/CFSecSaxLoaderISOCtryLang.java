
// Description: Java 25 XML SAX Element Handler for ISOCtryLang

/*
 *	server.markhome.mcf.CFSec
 *
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow
 *	
 *	Mark's Code Fractal 3.1 CFSec - Security Services
 *	
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow mark.sobkow@gmail.com
 *	
 *	These files are part of Mark's Code Fractal CFSec.
 *	
 *	Licensed under the Apache License, Version 2.0 (the "License");
 *	you may not use this file except in compliance with the License.
 *	You may obtain a copy of the License at
 *	
 *	http://www.apache.org/licenses/LICENSE-2.0
 *	
 *	Unless required by applicable law or agreed to in writing, software
 *	distributed under the License is distributed on an "AS IS" BASIS,
 *	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *	See the License for the specific language governing permissions and
 *	limitations under the License.
 *	
 */

package server.markhome.mcf.v3_1.cfsec.cfsecsaxloader;

import java.math.*;
import java.sql.*;
import java.text.*;
import java.time.*;
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import org.xml.sax.*;
import server.markhome.mcf.v3_1.cflib.*;
import server.markhome.mcf.v3_1.cflib.dbutil.*;
import server.markhome.mcf.v3_1.cflib.inz.Inz;
import server.markhome.mcf.v3_1.cflib.xml.*;
import server.markhome.mcf.v3_1.cfsec.cfsec.*;
import server.markhome.mcf.v3_1.cfsec.cfsecobj.*;

/*
 *	CFSecSaxLoaderISOCtryLangParse XML SAX Element Handler implementation
 *	for ISOCtryLang.
 */
public class CFSecSaxLoaderISOCtryLang
	extends CFLibXmlCoreElementHandler
{
	public CFSecSaxLoaderISOCtryLang( CFSecSaxLoader saxLoader ) {
		super( saxLoader );
	}

	public void startElement(
		String		uri,
		String		localName,
		String		qName,
		Attributes	attrs )
	throws SAXException
	{
		final String S_ProcName = "startElement";
		ICFSecISOCtryLangObj origBuff = null;
		ICFSecISOCtryLangEditObj editBuff = null;
		// Common XML Attributes
		String attrId = null;
		// ISOCtryLang Attributes
		String attrLang = null;
		// ISOCtryLang References
		ICFSecISOCtryObj refCtry = null;
		ICFSecISOLangObj refLang = null;
		// Attribute Extraction
		String attrLocalName;
		int numAttrs;
		int idxAttr;
		final String S_LocalName = "LocalName";
		try {
			assert qName.equals( "ISOCtryLang" );

			CFSecSaxLoader saxLoader = (CFSecSaxLoader)getParser();
			if( saxLoader == null ) {
				throw new CFLibNullArgumentException( getClass(),
					S_ProcName,
					0,
					"getParser()" );
			}

			ICFSecSchemaObj schemaObj = saxLoader.getSchemaObj();
			if( schemaObj == null ) {
				throw new CFLibNullArgumentException( getClass(),
					S_ProcName,
					0,
					"getParser().getSchemaObj()" );
			}

			// Instantiate an edit buffer for the parsed information
			origBuff = (ICFSecISOCtryLangObj)schemaObj.getISOCtryLangTableObj().newInstance();
			editBuff = (ICFSecISOCtryLangEditObj)origBuff.beginEdit();

			// Extract Attributes
			numAttrs = attrs.getLength();
			for( idxAttr = 0; idxAttr < numAttrs; idxAttr++ ) {
				attrLocalName = attrs.getLocalName( idxAttr );
				if( attrLocalName.equals( "Id" ) ) {
					if( attrId != null ) {
						throw new CFLibUniqueIndexViolationException( getClass(),
							S_ProcName,
							S_LocalName,
							attrLocalName );
					}
					attrId = attrs.getValue( idxAttr );
				}
				else if( attrLocalName.equals( "Lang" ) ) {
					if( attrLang != null ) {
						throw new CFLibUniqueIndexViolationException( getClass(),
							S_ProcName,
							S_LocalName,
							attrLocalName );
					}
					attrLang = attrs.getValue( idxAttr );
				}
				else if( attrLocalName.equals( "schemaLocation" ) ) {
					// ignored
				}
				else {
					throw new CFLibUnrecognizedAttributeException( getClass(),
						S_ProcName,
						getParser().getLocationInfo(),
						attrLocalName );
				}
			}

			// Ensure that required attributes have values
			if( ( attrLang == null ) || ( attrLang.length() <= 0 ) ) {
				throw new CFLibNullArgumentException( getClass(),
					S_ProcName,
					0,
					"Lang" );
			}

			// Save named attributes to context
			CFLibXmlCoreContext curContext = getParser().getCurContext();
			curContext.putNamedValue( "Id", attrId );
			curContext.putNamedValue( "Lang", attrLang );

			// Convert string attributes to native Java types
			// and apply the converted attributes to the editBuff.

			Integer natId;
			if( ( attrId != null ) && ( attrId.length() > 0 ) ) {
				natId = Integer.valueOf( Integer.parseInt( attrId ) );
			}
			else {
				natId = null;
			}
			// Get the scope/container object

			CFLibXmlCoreContext parentContext = curContext.getPrevContext();
			Object scopeObj;
			if( parentContext != null ) {
				scopeObj = parentContext.getNamedValue( "Object" );
			}
			else {
				scopeObj = null;
			}

			// Resolve and apply required Container reference

			if( scopeObj == null ) {
				throw new CFLibNullArgumentException( getClass(),
					S_ProcName,
					0,
					"scopeObj" );
			}
			else if( scopeObj instanceof ICFSecISOCtryObj ) {
				refCtry = (ICFSecISOCtryObj) scopeObj;
				editBuff.setRequiredContainerCtry( refCtry );
			}
			else {
				throw new CFLibUnsupportedClassException( getClass(),
					S_ProcName,
					"scopeObj",
					scopeObj,
					"ICFSecISOCtryObj" );
			}

			// Lookup refLang by key name value attr
			if( ( attrLang != null ) && ( attrLang.length() > 0 ) ) {
				refLang = (ICFSecISOLangObj)schemaObj.getISOLangTableObj().readISOLangByCode3Idx( attrLang );
				if( refLang == null ) {
					throw new CFLibNullArgumentException( getClass(),
						S_ProcName,
						0,
						"Resolve Lang reference named \"" + attrLang + "\" to table ISOLang" );
				}
			}
			else {
				refLang = null;
			}
			editBuff.setRequiredParentLang( refLang );

			CFSecSaxLoader.LoaderBehaviourEnum loaderBehaviour = saxLoader.getISOCtryLangLoaderBehaviour();
			ICFSecISOCtryLangEditObj editISOCtryLang = null;
			ICFSecISOCtryLangObj origISOCtryLang = (ICFSecISOCtryLangObj)schemaObj.getISOCtryLangTableObj().readISOCtryLangByIdIdx( refCtry.getRequiredISOCtryId(),
			refLang.getRequiredISOLangId() );
			if( origISOCtryLang == null ) {
				editISOCtryLang = editBuff;
			}
			else {
				switch( loaderBehaviour ) {
					case Insert:
						break;
					case Update:
						editISOCtryLang = (ICFSecISOCtryLangEditObj)origISOCtryLang.beginEdit();
						editISOCtryLang.setRequiredParentLang( editBuff.getRequiredParentLang() );
						break;
					case Replace:
						editISOCtryLang = (ICFSecISOCtryLangEditObj)origISOCtryLang.beginEdit();
						editISOCtryLang.deleteInstance();
						editISOCtryLang = null;
						origISOCtryLang = null;
						editISOCtryLang = editBuff;
						break;
				}
			}

			if( editISOCtryLang != null ) {
				if( origISOCtryLang != null ) {
					editISOCtryLang.update();
				}
				else {
					origISOCtryLang = (ICFSecISOCtryLangObj)editISOCtryLang.create();
				}
				editISOCtryLang = null;
			}

			curContext.putNamedValue( "Object", origISOCtryLang );
		}
		catch( RuntimeException e ) {
			throw new SAXException( "Near " + getParser().getLocationInfo() + ": Caught and rethrew " + e.getClass().getName() + " - " + e.getMessage(),
				e );
		}
		catch( Error e ) {
			throw new SAXException( "Near " + getParser().getLocationInfo() + ": Caught and rethrew " + e.getClass().getName() + " - " + e.getMessage() );
		}
	}

	public void endElement(
		String		uri,
		String		localName,
		String		qName )
	throws SAXException
	{
	}
}
