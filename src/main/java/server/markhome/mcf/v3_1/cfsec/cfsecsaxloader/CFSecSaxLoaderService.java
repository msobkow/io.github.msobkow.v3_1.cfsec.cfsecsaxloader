
// Description: Java 25 XML SAX Element Handler for Service

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
 *	CFSecSaxLoaderServiceParse XML SAX Element Handler implementation
 *	for Service.
 */
public class CFSecSaxLoaderService
	extends CFLibXmlCoreElementHandler
{
	public CFSecSaxLoaderService( CFSecSaxLoader saxLoader ) {
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
		ICFSecServiceObj origBuff = null;
		ICFSecServiceEditObj editBuff = null;
		// Common XML Attributes
		String attrId = null;
		// Service Attributes
		String attrHostPort = null;
		String attrServiceType = null;
		// Service References
		ICFSecClusterObj refCluster = null;
		ICFSecHostNodeObj refHost = null;
		ICFSecServiceTypeObj refServiceType = null;
		// Attribute Extraction
		String attrLocalName;
		int numAttrs;
		int idxAttr;
		final String S_LocalName = "LocalName";
		try {
			assert qName.equals( "Service" );

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
			origBuff = (ICFSecServiceObj)schemaObj.getServiceTableObj().newInstance();
			editBuff = (ICFSecServiceEditObj)origBuff.beginEdit();

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
				else if( attrLocalName.equals( "HostPort" ) ) {
					if( attrHostPort != null ) {
						throw new CFLibUniqueIndexViolationException( getClass(),
							S_ProcName,
							S_LocalName,
							attrLocalName );
					}
					attrHostPort = attrs.getValue( idxAttr );
				}
				else if( attrLocalName.equals( "ServiceType" ) ) {
					if( attrServiceType != null ) {
						throw new CFLibUniqueIndexViolationException( getClass(),
							S_ProcName,
							S_LocalName,
							attrLocalName );
					}
					attrServiceType = attrs.getValue( idxAttr );
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
			if( ( attrHostPort == null ) || ( attrHostPort.length() <= 0 ) ) {
				throw new CFLibNullArgumentException( getClass(),
					S_ProcName,
					0,
					"HostPort" );
			}

			// Save named attributes to context
			CFLibXmlCoreContext curContext = getParser().getCurContext();
			curContext.putNamedValue( "Id", attrId );
			curContext.putNamedValue( "HostPort", attrHostPort );
			curContext.putNamedValue( "ServiceType", attrServiceType );

			// Convert string attributes to native Java types
			// and apply the converted attributes to the editBuff.

			Integer natId;
			if( ( attrId != null ) && ( attrId.length() > 0 ) ) {
				natId = Integer.valueOf( Integer.parseInt( attrId ) );
			}
			else {
				natId = null;
			}
			short natHostPort = Short.parseShort( attrHostPort );
			editBuff.setRequiredHostPort( natHostPort );

			// Get the scope/container object

			CFLibXmlCoreContext parentContext = curContext.getPrevContext();
			Object scopeObj;
			if( parentContext != null ) {
				scopeObj = parentContext.getNamedValue( "Object" );
			}
			else {
				scopeObj = null;
			}

			// Resolve and apply optional Container reference

			if( scopeObj == null ) {
				refHost = null;
				editBuff.setOptionalContainerHost( refHost );
				refCluster = (ICFSecClusterObj)editBuff.getRequiredOwnerCluster();
			}
			else if( scopeObj instanceof ICFSecHostNodeObj ) {
				refHost = (ICFSecHostNodeObj) scopeObj;
				editBuff.setOptionalContainerHost( refHost );
				refCluster = (ICFSecClusterObj)editBuff.getRequiredOwnerCluster();
			}
			else {
				throw new CFLibUnsupportedClassException( getClass(),
					S_ProcName,
					"scopeObj",
					scopeObj,
					"ICFSecHostNodeObj" );
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

			// Lookup refServiceType by key name value attr
			if( ( attrServiceType != null ) && ( attrServiceType.length() > 0 ) ) {
				refServiceType = (ICFSecServiceTypeObj)schemaObj.getServiceTypeTableObj().readServiceTypeByUDescrIdx( attrServiceType );
				if( refServiceType == null ) {
					throw new CFLibNullArgumentException( getClass(),
						S_ProcName,
						0,
						"Resolve ServiceType reference named \"" + attrServiceType + "\" to table ServiceType" );
				}
			}
			else {
				refServiceType = null;
			}
			editBuff.setOptionalParentServiceType( refServiceType );

			CFSecSaxLoader.LoaderBehaviourEnum loaderBehaviour = saxLoader.getServiceLoaderBehaviour();
			ICFSecServiceEditObj editService = null;
			ICFSecServiceObj origService = (ICFSecServiceObj)schemaObj.getServiceTableObj().readServiceByUTypeIdx( refCluster.getRequiredId(),
			refHost.getRequiredHostNodeId(),
			refServiceType.getRequiredServiceTypeId() );
			if( origService == null ) {
				editService = editBuff;
			}
			else {
				switch( loaderBehaviour ) {
					case Insert:
						break;
					case Update:
						editService = (ICFSecServiceEditObj)origService.beginEdit();
						editService.setRequiredHostPort( editBuff.getRequiredHostPort() );
						editService.setOptionalParentServiceType( editBuff.getOptionalParentServiceType() );
						break;
					case Replace:
						editService = (ICFSecServiceEditObj)origService.beginEdit();
						editService.deleteInstance();
						editService = null;
						origService = null;
						editService = editBuff;
						break;
				}
			}

			if( editService != null ) {
				if( origService != null ) {
					editService.update();
				}
				else {
					origService = (ICFSecServiceObj)editService.create();
				}
				editService = null;
			}

			curContext.putNamedValue( "Object", origService );
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
