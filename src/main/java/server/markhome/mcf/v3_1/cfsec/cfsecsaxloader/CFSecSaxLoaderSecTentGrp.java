
// Description: Java 25 XML SAX Element Handler for SecTentGrp

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
 *	CFSecSaxLoaderSecTentGrpParse XML SAX Element Handler implementation
 *	for SecTentGrp.
 */
public class CFSecSaxLoaderSecTentGrp
	extends CFLibXmlCoreElementHandler
{
	public CFSecSaxLoaderSecTentGrp( CFSecSaxLoader saxLoader ) {
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
		ICFSecSecTentGrpObj origBuff = null;
		ICFSecSecTentGrpEditObj editBuff = null;
		// Common XML Attributes
		String attrId = null;
		// SecTentGrp Attributes
		String attrTenantId = null;
		String attrName = null;
		// SecTentGrp References
		// Attribute Extraction
		String attrLocalName;
		int numAttrs;
		int idxAttr;
		final String S_LocalName = "LocalName";
		try {
			assert qName.equals( "SecTentGrp" );

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
			origBuff = (ICFSecSecTentGrpObj)schemaObj.getSecTentGrpTableObj().newInstance();
			editBuff = (ICFSecSecTentGrpEditObj)origBuff.beginEdit();

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
				else if( attrLocalName.equals( "TenantId" ) ) {
					if( attrTenantId != null ) {
						throw new CFLibUniqueIndexViolationException( getClass(),
							S_ProcName,
							S_LocalName,
							attrLocalName );
					}
					attrTenantId = attrs.getValue( idxAttr );
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
			if( ( attrTenantId == null ) || ( attrTenantId.length() <= 0 ) ) {
				throw new CFLibNullArgumentException( getClass(),
					S_ProcName,
					0,
					"TenantId" );
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
			curContext.putNamedValue( "TenantId", attrTenantId );
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
			CFLibDbKeyHash256 natTenantId;
			try {
				natTenantId = CFLibDbKeyHash256.fromHex( attrTenantId );
			}
			catch( RuntimeException e ) {
				throw new CFLibInvalidArgumentException( getClass(),
					S_ProcName,
					0,
					"TenantId",
					e );
			}
			editBuff.setRequiredTenantId( natTenantId );

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

			CFSecSaxLoader.LoaderBehaviourEnum loaderBehaviour = saxLoader.getSecTentGrpLoaderBehaviour();
			ICFSecSecTentGrpEditObj editSecTentGrp = null;
			ICFSecSecTentGrpObj origSecTentGrp = (ICFSecSecTentGrpObj)schemaObj.getSecTentGrpTableObj().readSecTentGrpByUNameIdx( editBuff.getRequiredTenantId(),
			editBuff.getRequiredName() );
			if( origSecTentGrp == null ) {
				editSecTentGrp = editBuff;
			}
			else {
				switch( loaderBehaviour ) {
					case Insert:
						break;
					case Update:
						editSecTentGrp = (ICFSecSecTentGrpEditObj)origSecTentGrp.beginEdit();
						editSecTentGrp.setRequiredTenantId( editBuff.getRequiredTenantId() );
						editSecTentGrp.setRequiredName( editBuff.getRequiredName() );
						break;
					case Replace:
						editSecTentGrp = (ICFSecSecTentGrpEditObj)origSecTentGrp.beginEdit();
						editSecTentGrp.deleteInstance();
						editSecTentGrp = null;
						origSecTentGrp = null;
						editSecTentGrp = editBuff;
						break;
				}
			}

			if( editSecTentGrp != null ) {
				if( origSecTentGrp != null ) {
					editSecTentGrp.update();
				}
				else {
					origSecTentGrp = (ICFSecSecTentGrpObj)editSecTentGrp.create();
				}
				editSecTentGrp = null;
			}

			curContext.putNamedValue( "Object", origSecTentGrp );
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
