
// Description: Java 25 XML SAX Element Handler for SecClusGrp

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
 *	CFSecSaxLoaderSecClusGrpParse XML SAX Element Handler implementation
 *	for SecClusGrp.
 */
public class CFSecSaxLoaderSecClusGrp
	extends CFLibXmlCoreElementHandler
{
	public CFSecSaxLoaderSecClusGrp( CFSecSaxLoader saxLoader ) {
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
		ICFSecSecClusGrpObj origBuff = null;
		ICFSecSecClusGrpEditObj editBuff = null;
		// Common XML Attributes
		String attrId = null;
		// SecClusGrp Attributes
		String attrSysGrp = null;
		// SecClusGrp References
		ICFSecClusterObj refCluster = null;
		ICFSecSecSysGrpObj refSysGrp = null;
		// Attribute Extraction
		String attrLocalName;
		int numAttrs;
		int idxAttr;
		final String S_LocalName = "LocalName";
		try {
			assert qName.equals( "SecClusGrp" );

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
			origBuff = (ICFSecSecClusGrpObj)schemaObj.getSecClusGrpTableObj().newInstance();
			editBuff = (ICFSecSecClusGrpEditObj)origBuff.beginEdit();

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
				else if( attrLocalName.equals( "SysGrp" ) ) {
					if( attrSysGrp != null ) {
						throw new CFLibUniqueIndexViolationException( getClass(),
							S_ProcName,
							S_LocalName,
							attrLocalName );
					}
					attrSysGrp = attrs.getValue( idxAttr );
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
			if( ( attrSysGrp == null ) || ( attrSysGrp.length() <= 0 ) ) {
				throw new CFLibNullArgumentException( getClass(),
					S_ProcName,
					0,
					"SysGrp" );
			}

			// Save named attributes to context
			CFLibXmlCoreContext curContext = getParser().getCurContext();
			curContext.putNamedValue( "Id", attrId );
			curContext.putNamedValue( "SysGrp", attrSysGrp );

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

			refCluster = null;
			// Resolve and apply Owner reference

			if( refCluster == null ) {
				if( scopeObj instanceof ICFSecClusterObj ) {
					refCluster = (ICFSecClusterObj) scopeObj;
					editBuff.setRequiredOwnerCluster( refCluster );
				}
				else {
					throw new CFLibNullArgumentException( getClass(),
						S_ProcName,
						0,
						"Owner<Cluster>" );
				}
			}

			// Lookup refSysGrp by key name value attr
			if( ( attrSysGrp != null ) && ( attrSysGrp.length() > 0 ) ) {
				refSysGrp = (ICFSecSecSysGrpObj)schemaObj.getSecSysGrpTableObj().readSecSysGrpByUNameIdx( attrSysGrp );
				if( refSysGrp == null ) {
					throw new CFLibNullArgumentException( getClass(),
						S_ProcName,
						0,
						"Resolve SysGrp reference named \"" + attrSysGrp + "\" to table SecSysGrp" );
				}
			}
			else {
				refSysGrp = null;
			}
			editBuff.setRequiredParentSysGrp( refSysGrp );

			CFSecSaxLoader.LoaderBehaviourEnum loaderBehaviour = saxLoader.getSecClusGrpLoaderBehaviour();
			ICFSecSecClusGrpEditObj editSecClusGrp = null;
			ICFSecSecClusGrpObj origSecClusGrp = (ICFSecSecClusGrpObj)schemaObj.getSecClusGrpTableObj().readSecClusGrpByUNameIdx( refCluster.getRequiredId(),
			refSysGrp.getRequiredName() );
			if( origSecClusGrp == null ) {
				editSecClusGrp = editBuff;
			}
			else {
				switch( loaderBehaviour ) {
					case Insert:
						break;
					case Update:
						editSecClusGrp = (ICFSecSecClusGrpEditObj)origSecClusGrp.beginEdit();
						editSecClusGrp.setRequiredParentSysGrp( editBuff.getRequiredParentSysGrp() );
						break;
					case Replace:
						editSecClusGrp = (ICFSecSecClusGrpEditObj)origSecClusGrp.beginEdit();
						editSecClusGrp.deleteInstance();
						editSecClusGrp = null;
						origSecClusGrp = null;
						editSecClusGrp = editBuff;
						break;
				}
			}

			if( editSecClusGrp != null ) {
				if( origSecClusGrp != null ) {
					editSecClusGrp.update();
				}
				else {
					origSecClusGrp = (ICFSecSecClusGrpObj)editSecClusGrp.create();
				}
				editSecClusGrp = null;
			}

			curContext.putNamedValue( "Object", origSecClusGrp );
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
