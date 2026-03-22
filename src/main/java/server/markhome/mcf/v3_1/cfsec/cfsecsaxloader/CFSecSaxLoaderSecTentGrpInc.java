
// Description: Java 25 XML SAX Element Handler for SecTentGrpInc

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
 *	CFSecSaxLoaderSecTentGrpIncParse XML SAX Element Handler implementation
 *	for SecTentGrpInc.
 */
public class CFSecSaxLoaderSecTentGrpInc
	extends CFLibXmlCoreElementHandler
{
	public CFSecSaxLoaderSecTentGrpInc( CFSecSaxLoader saxLoader ) {
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
		ICFSecSecTentGrpIncObj origBuff = null;
		ICFSecSecTentGrpIncEditObj editBuff = null;
		// Common XML Attributes
		String attrId = null;
		// SecTentGrpInc Attributes
		// SecTentGrpInc References
		// Attribute Extraction
		String attrLocalName;
		int numAttrs;
		int idxAttr;
		final String S_LocalName = "LocalName";
		try {
			assert qName.equals( "SecTentGrpInc" );

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
			origBuff = (ICFSecSecTentGrpIncObj)schemaObj.getSecTentGrpIncTableObj().newInstance();
			editBuff = (ICFSecSecTentGrpIncEditObj)origBuff.beginEdit();

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

			// Save named attributes to context
			CFLibXmlCoreContext curContext = getParser().getCurContext();
			curContext.putNamedValue( "Id", attrId );

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

			CFSecSaxLoader.LoaderBehaviourEnum loaderBehaviour = saxLoader.getSecTentGrpIncLoaderBehaviour();
			ICFSecSecTentGrpIncEditObj editSecTentGrpInc = null;
			ICFSecSecTentGrpIncObj origSecTentGrpInc = (ICFSecSecTentGrpIncObj)schemaObj.getSecTentGrpIncTableObj().readSecTentGrpIncByIdIdx( editBuff.getRequiredSecTentGrpId(),
			editBuff.getRequiredIncName() );
			if( origSecTentGrpInc == null ) {
				editSecTentGrpInc = editBuff;
			}
			else {
				switch( loaderBehaviour ) {
					case Insert:
						break;
					case Update:
						editSecTentGrpInc = (ICFSecSecTentGrpIncEditObj)origSecTentGrpInc.beginEdit();
						break;
					case Replace:
						editSecTentGrpInc = (ICFSecSecTentGrpIncEditObj)origSecTentGrpInc.beginEdit();
						editSecTentGrpInc.deleteInstance();
						editSecTentGrpInc = null;
						origSecTentGrpInc = null;
						editSecTentGrpInc = editBuff;
						break;
				}
			}

			if( editSecTentGrpInc != null ) {
				if( origSecTentGrpInc != null ) {
					editSecTentGrpInc.update();
				}
				else {
					origSecTentGrpInc = (ICFSecSecTentGrpIncObj)editSecTentGrpInc.create();
				}
				editSecTentGrpInc = null;
			}

			curContext.putNamedValue( "Object", origSecTentGrpInc );
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
