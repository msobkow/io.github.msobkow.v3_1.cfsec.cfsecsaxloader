
// Description: Java 25 XML SAX Element Handler for ISOLang

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
 *	CFSecSaxLoaderISOLangParse XML SAX Element Handler implementation
 *	for ISOLang.
 */
public class CFSecSaxLoaderISOLang
	extends CFLibXmlCoreElementHandler
{
	public CFSecSaxLoaderISOLang( CFSecSaxLoader saxLoader ) {
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
		ICFSecISOLangObj origBuff = null;
		ICFSecISOLangEditObj editBuff = null;
		// Common XML Attributes
		String attrId = null;
		// ISOLang Attributes
		String attrISO6392Code = null;
		String attrISO6391Code = null;
		String attrEnglishName = null;
		// ISOLang References
		// Attribute Extraction
		String attrLocalName;
		int numAttrs;
		int idxAttr;
		final String S_LocalName = "LocalName";
		try {
			assert qName.equals( "ISOLang" );

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
			origBuff = (ICFSecISOLangObj)schemaObj.getISOLangTableObj().newInstance();
			editBuff = (ICFSecISOLangEditObj)origBuff.beginEdit();

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
				else if( attrLocalName.equals( "ISO6392Code" ) ) {
					if( attrISO6392Code != null ) {
						throw new CFLibUniqueIndexViolationException( getClass(),
							S_ProcName,
							S_LocalName,
							attrLocalName );
					}
					attrISO6392Code = attrs.getValue( idxAttr );
				}
				else if( attrLocalName.equals( "ISO6391Code" ) ) {
					if( attrISO6391Code != null ) {
						throw new CFLibUniqueIndexViolationException( getClass(),
							S_ProcName,
							S_LocalName,
							attrLocalName );
					}
					attrISO6391Code = attrs.getValue( idxAttr );
				}
				else if( attrLocalName.equals( "EnglishName" ) ) {
					if( attrEnglishName != null ) {
						throw new CFLibUniqueIndexViolationException( getClass(),
							S_ProcName,
							S_LocalName,
							attrLocalName );
					}
					attrEnglishName = attrs.getValue( idxAttr );
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
			if( attrISO6392Code == null ) {
				throw new CFLibNullArgumentException( getClass(),
					S_ProcName,
					0,
					"ISO6392Code" );
			}
			if( attrEnglishName == null ) {
				throw new CFLibNullArgumentException( getClass(),
					S_ProcName,
					0,
					"EnglishName" );
			}

			// Save named attributes to context
			CFLibXmlCoreContext curContext = getParser().getCurContext();
			curContext.putNamedValue( "Id", attrId );
			curContext.putNamedValue( "ISO6392Code", attrISO6392Code );
			curContext.putNamedValue( "ISO6391Code", attrISO6391Code );
			curContext.putNamedValue( "EnglishName", attrEnglishName );

			// Convert string attributes to native Java types
			// and apply the converted attributes to the editBuff.

			Integer natId;
			if( ( attrId != null ) && ( attrId.length() > 0 ) ) {
				natId = Integer.valueOf( Integer.parseInt( attrId ) );
			}
			else {
				natId = null;
			}
			String natISO6392Code = attrISO6392Code;
			editBuff.setRequiredISO6392Code( natISO6392Code );

			String natISO6391Code = attrISO6391Code;
			editBuff.setOptionalISO6391Code( natISO6391Code );

			String natEnglishName = attrEnglishName;
			editBuff.setRequiredEnglishName( natEnglishName );

			// Get the scope/container object

			CFLibXmlCoreContext parentContext = curContext.getPrevContext();
			Object scopeObj;
			if( parentContext != null ) {
				scopeObj = parentContext.getNamedValue( "Object" );
			}
			else {
				scopeObj = null;
			}

			CFSecSaxLoader.LoaderBehaviourEnum loaderBehaviour = saxLoader.getISOLangLoaderBehaviour();
			ICFSecISOLangEditObj editISOLang = null;
			ICFSecISOLangObj origISOLang = (ICFSecISOLangObj)schemaObj.getISOLangTableObj().readISOLangByCode3Idx( editBuff.getRequiredISO6392Code() );
			if( origISOLang == null ) {
				editISOLang = editBuff;
			}
			else {
				switch( loaderBehaviour ) {
					case Insert:
						break;
					case Update:
						editISOLang = (ICFSecISOLangEditObj)origISOLang.beginEdit();
						editISOLang.setRequiredISO6392Code( editBuff.getRequiredISO6392Code() );
						editISOLang.setOptionalISO6391Code( editBuff.getOptionalISO6391Code() );
						editISOLang.setRequiredEnglishName( editBuff.getRequiredEnglishName() );
						break;
					case Replace:
						editISOLang = (ICFSecISOLangEditObj)origISOLang.beginEdit();
						editISOLang.deleteInstance();
						editISOLang = null;
						origISOLang = null;
						editISOLang = editBuff;
						break;
				}
			}

			if( editISOLang != null ) {
				if( origISOLang != null ) {
					editISOLang.update();
				}
				else {
					origISOLang = (ICFSecISOLangObj)editISOLang.create();
				}
				editISOLang = null;
			}

			curContext.putNamedValue( "Object", origISOLang );
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
