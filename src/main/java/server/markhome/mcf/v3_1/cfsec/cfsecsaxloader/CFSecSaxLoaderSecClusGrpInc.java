
// Description: Java 25 XML SAX Element Handler for SecClusGrpInc

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
 *	CFSecSaxLoaderSecClusGrpIncParse XML SAX Element Handler implementation
 *	for SecClusGrpInc.
 */
public class CFSecSaxLoaderSecClusGrpInc
	extends CFLibXmlCoreElementHandler
{
	public CFSecSaxLoaderSecClusGrpInc( CFSecSaxLoader saxLoader ) {
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
		ICFSecSecClusGrpIncObj origBuff = null;
		ICFSecSecClusGrpIncEditObj editBuff = null;
		// Common XML Attributes
		String attrId = null;
		// SecClusGrpInc Attributes
		// SecClusGrpInc References
		// Attribute Extraction
		String attrLocalName;
		int numAttrs;
		int idxAttr;
		final String S_LocalName = "LocalName";
		try {
			assert qName.equals( "SecClusGrpInc" );

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
			origBuff = (ICFSecSecClusGrpIncObj)schemaObj.getSecClusGrpIncTableObj().newInstance();
			editBuff = (ICFSecSecClusGrpIncEditObj)origBuff.beginEdit();

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

			CFSecSaxLoader.LoaderBehaviourEnum loaderBehaviour = saxLoader.getSecClusGrpIncLoaderBehaviour();
			ICFSecSecClusGrpIncEditObj editSecClusGrpInc = null;
			ICFSecSecClusGrpIncObj origSecClusGrpInc = (ICFSecSecClusGrpIncObj)schemaObj.getSecClusGrpIncTableObj().readSecClusGrpIncByIdIdx( editBuff.getRequiredSecClusGrpId(),
			editBuff.getRequiredIncName() );
			if( origSecClusGrpInc == null ) {
				editSecClusGrpInc = editBuff;
			}
			else {
				switch( loaderBehaviour ) {
					case Insert:
						break;
					case Update:
						editSecClusGrpInc = (ICFSecSecClusGrpIncEditObj)origSecClusGrpInc.beginEdit();
						break;
					case Replace:
						editSecClusGrpInc = (ICFSecSecClusGrpIncEditObj)origSecClusGrpInc.beginEdit();
						editSecClusGrpInc.deleteInstance();
						editSecClusGrpInc = null;
						origSecClusGrpInc = null;
						editSecClusGrpInc = editBuff;
						break;
				}
			}

			if( editSecClusGrpInc != null ) {
				if( origSecClusGrpInc != null ) {
					editSecClusGrpInc.update();
				}
				else {
					origSecClusGrpInc = (ICFSecSecClusGrpIncObj)editSecClusGrpInc.create();
				}
				editSecClusGrpInc = null;
			}

			curContext.putNamedValue( "Object", origSecClusGrpInc );
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
