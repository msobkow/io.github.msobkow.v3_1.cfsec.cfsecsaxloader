
// Description: Java 25 XML SAX Element Handler for SecGrpInc

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
 *	CFSecSaxLoaderSecGrpIncParse XML SAX Element Handler implementation
 *	for SecGrpInc.
 */
public class CFSecSaxLoaderSecGrpInc
	extends CFLibXmlCoreElementHandler
{
	public CFSecSaxLoaderSecGrpInc( CFSecSaxLoader saxLoader ) {
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
		ICFSecSecGrpIncObj origBuff = null;
		ICFSecSecGrpIncEditObj editBuff = null;
		// Common XML Attributes
		String attrId = null;
		// SecGrpInc Attributes
		String attrSubGroup = null;
		// SecGrpInc References
		ICFSecClusterObj refCluster = null;
		ICFSecSecGroupObj refGroup = null;
		ICFSecSecGroupObj refSubGroup = null;
		// Attribute Extraction
		String attrLocalName;
		int numAttrs;
		int idxAttr;
		final String S_LocalName = "LocalName";
		try {
			assert qName.equals( "SecGrpInc" );

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
			origBuff = (ICFSecSecGrpIncObj)schemaObj.getSecGrpIncTableObj().newInstance();
			editBuff = (ICFSecSecGrpIncEditObj)origBuff.beginEdit();

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
				else if( attrLocalName.equals( "SubGroup" ) ) {
					if( attrSubGroup != null ) {
						throw new CFLibUniqueIndexViolationException( getClass(),
							S_ProcName,
							S_LocalName,
							attrLocalName );
					}
					attrSubGroup = attrs.getValue( idxAttr );
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
			if( ( attrSubGroup == null ) || ( attrSubGroup.length() <= 0 ) ) {
				throw new CFLibNullArgumentException( getClass(),
					S_ProcName,
					0,
					"SubGroup" );
			}

			// Save named attributes to context
			CFLibXmlCoreContext curContext = getParser().getCurContext();
			curContext.putNamedValue( "Id", attrId );
			curContext.putNamedValue( "SubGroup", attrSubGroup );

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
			else if( scopeObj instanceof ICFSecSecGroupObj ) {
				refGroup = (ICFSecSecGroupObj) scopeObj;
				editBuff.setRequiredContainerGroup( refGroup );
				refCluster = (ICFSecClusterObj)editBuff.getRequiredOwnerCluster();
			}
			else {
				throw new CFLibUnsupportedClassException( getClass(),
					S_ProcName,
					"scopeObj",
					scopeObj,
					"ICFSecSecGroupObj" );
			}

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

			// Lookup refSubGroup by key name value attr
			if( ( attrSubGroup != null ) && ( attrSubGroup.length() > 0 ) ) {
				refSubGroup = (ICFSecSecGroupObj)schemaObj.getSecGroupTableObj().readSecGroupByUNameIdx( editBuff.getRequiredClusterId(),
				attrSubGroup );
				if( refSubGroup == null ) {
					throw new CFLibNullArgumentException( getClass(),
						S_ProcName,
						0,
						"Resolve SubGroup reference named \"" + attrSubGroup + "\" to table SecGroup" );
				}
			}
			else {
				refSubGroup = null;
			}
			editBuff.setRequiredParentSubGroup( refSubGroup );

			CFSecSaxLoader.LoaderBehaviourEnum loaderBehaviour = saxLoader.getSecGrpIncLoaderBehaviour();
			ICFSecSecGrpIncEditObj editSecGrpInc = null;
			ICFSecSecGrpIncObj origSecGrpInc = (ICFSecSecGrpIncObj)schemaObj.getSecGrpIncTableObj().readSecGrpIncByUIncludeIdx( refCluster.getRequiredId(),
			refGroup.getRequiredSecGroupId(),
			refSubGroup.getRequiredSecGroupId() );
			if( origSecGrpInc == null ) {
				editSecGrpInc = editBuff;
			}
			else {
				switch( loaderBehaviour ) {
					case Insert:
						break;
					case Update:
						editSecGrpInc = (ICFSecSecGrpIncEditObj)origSecGrpInc.beginEdit();
						editSecGrpInc.setRequiredParentSubGroup( editBuff.getRequiredParentSubGroup() );
						break;
					case Replace:
						editSecGrpInc = (ICFSecSecGrpIncEditObj)origSecGrpInc.beginEdit();
						editSecGrpInc.deleteInstance();
						editSecGrpInc = null;
						origSecGrpInc = null;
						editSecGrpInc = editBuff;
						break;
				}
			}

			if( editSecGrpInc != null ) {
				if( origSecGrpInc != null ) {
					editSecGrpInc.update();
				}
				else {
					origSecGrpInc = (ICFSecSecGrpIncObj)editSecGrpInc.create();
				}
				editSecGrpInc = null;
			}

			curContext.putNamedValue( "Object", origSecGrpInc );
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
