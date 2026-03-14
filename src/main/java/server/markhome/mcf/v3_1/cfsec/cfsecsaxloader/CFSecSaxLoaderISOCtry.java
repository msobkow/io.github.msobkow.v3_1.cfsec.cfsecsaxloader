
// Description: Java 25 XML SAX Element Handler for ISOCtry

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
 *	CFSecSaxLoaderISOCtryParse XML SAX Element Handler implementation
 *	for ISOCtry.
 */
public class CFSecSaxLoaderISOCtry
	extends CFLibXmlCoreElementHandler
{
	public CFSecSaxLoaderISOCtry( CFSecSaxLoader saxLoader ) {
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
		ICFSecISOCtryObj origBuff = null;
		ICFSecISOCtryEditObj editBuff = null;
		// Common XML Attributes
		String attrId = null;
		// ISOCtry Attributes
		String attrISOCode = null;
		String attrName = null;
		// ISOCtry References
		// Attribute Extraction
		String attrLocalName;
		int numAttrs;
		int idxAttr;
		final String S_LocalName = "LocalName";
		try {
			assert qName.equals( "ISOCtry" );

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
			origBuff = (ICFSecISOCtryObj)schemaObj.getISOCtryTableObj().newInstance();
			editBuff = (ICFSecISOCtryEditObj)origBuff.beginEdit();

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
				else if( attrLocalName.equals( "ISOCode" ) ) {
					if( attrISOCode != null ) {
						throw new CFLibUniqueIndexViolationException( getClass(),
							S_ProcName,
							S_LocalName,
							attrLocalName );
					}
					attrISOCode = attrs.getValue( idxAttr );
				}
				else if( attrLocalName.equals( "Name" ) ) {
					if( attrName != null ) {
						throw new CFLibUniqueIndexViolationException( getClass(),
							S_ProcName,
							S_LocalName,
							attrLocalName );
					}
					attrName = attrs.getValue( idxAttr );
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
			if( attrISOCode == null ) {
				throw new CFLibNullArgumentException( getClass(),
					S_ProcName,
					0,
					"ISOCode" );
			}
			if( attrName == null ) {
				throw new CFLibNullArgumentException( getClass(),
					S_ProcName,
					0,
					"Name" );
			}

			// Save named attributes to context
			CFLibXmlCoreContext curContext = getParser().getCurContext();
			curContext.putNamedValue( "Id", attrId );
			curContext.putNamedValue( "ISOCode", attrISOCode );
			curContext.putNamedValue( "Name", attrName );

			// Convert string attributes to native Java types
			// and apply the converted attributes to the editBuff.

			Integer natId;
			if( ( attrId != null ) && ( attrId.length() > 0 ) ) {
				natId = Integer.valueOf( Integer.parseInt( attrId ) );
			}
			else {
				natId = null;
			}
			String natISOCode = attrISOCode;
			editBuff.setRequiredISOCode( natISOCode );

			String natName = attrName;
			editBuff.setRequiredName( natName );

			// Get the scope/container object

			CFLibXmlCoreContext parentContext = curContext.getPrevContext();
			Object scopeObj;
			if( parentContext != null ) {
				scopeObj = parentContext.getNamedValue( "Object" );
			}
			else {
				scopeObj = null;
			}

			CFSecSaxLoader.LoaderBehaviourEnum loaderBehaviour = saxLoader.getISOCtryLoaderBehaviour();
			ICFSecISOCtryEditObj editISOCtry = null;
			ICFSecISOCtryObj origISOCtry = (ICFSecISOCtryObj)schemaObj.getISOCtryTableObj().readISOCtryByISOCodeIdx( editBuff.getRequiredISOCode() );
			if( origISOCtry == null ) {
				editISOCtry = editBuff;
			}
			else {
				switch( loaderBehaviour ) {
					case Insert:
						break;
					case Update:
						editISOCtry = (ICFSecISOCtryEditObj)origISOCtry.beginEdit();
						editISOCtry.setRequiredISOCode( editBuff.getRequiredISOCode() );
						editISOCtry.setRequiredName( editBuff.getRequiredName() );
						break;
					case Replace:
						editISOCtry = (ICFSecISOCtryEditObj)origISOCtry.beginEdit();
						editISOCtry.deleteInstance();
						editISOCtry = null;
						origISOCtry = null;
						editISOCtry = editBuff;
						break;
				}
			}

			if( editISOCtry != null ) {
				if( origISOCtry != null ) {
					editISOCtry.update();
				}
				else {
					origISOCtry = (ICFSecISOCtryObj)editISOCtry.create();
				}
				editISOCtry = null;
			}

			curContext.putNamedValue( "Object", origISOCtry );
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
