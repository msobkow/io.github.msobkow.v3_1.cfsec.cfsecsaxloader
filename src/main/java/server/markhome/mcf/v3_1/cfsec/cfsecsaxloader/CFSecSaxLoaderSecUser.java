
// Description: Java 25 XML SAX Element Handler for SecUser

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
 *	CFSecSaxLoaderSecUserParse XML SAX Element Handler implementation
 *	for SecUser.
 */
public class CFSecSaxLoaderSecUser
	extends CFLibXmlCoreElementHandler
{
	public CFSecSaxLoaderSecUser( CFSecSaxLoader saxLoader ) {
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
		ICFSecSecUserObj origBuff = null;
		ICFSecSecUserEditObj editBuff = null;
		// Common XML Attributes
		String attrId = null;
		// SecUser Attributes
		String attrLoginId = null;
		String attrDfltSysGrpName = null;
		String attrDfltClusGrpName = null;
		String attrDfltTentGrpName = null;
		String attrEMailAddress = null;
		String attrEMConf = null;
		String attrPWReset = null;
		// SecUser References
		// Attribute Extraction
		String attrLocalName;
		int numAttrs;
		int idxAttr;
		final String S_LocalName = "LocalName";
		try {
			assert qName.equals( "SecUser" );

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
			origBuff = (ICFSecSecUserObj)schemaObj.getSecUserTableObj().newInstance();
			editBuff = (ICFSecSecUserEditObj)origBuff.beginEdit();

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
				else if( attrLocalName.equals( "LoginId" ) ) {
					if( attrLoginId != null ) {
						throw new CFLibUniqueIndexViolationException( getClass(),
							S_ProcName,
							S_LocalName,
							attrLocalName );
					}
					attrLoginId = attrs.getValue( idxAttr );
				}
				else if( attrLocalName.equals( "DfltSysGrpName" ) ) {
					if( attrDfltSysGrpName != null ) {
						throw new CFLibUniqueIndexViolationException( getClass(),
							S_ProcName,
							S_LocalName,
							attrLocalName );
					}
					attrDfltSysGrpName = attrs.getValue( idxAttr );
				}
				else if( attrLocalName.equals( "DfltClusGrpName" ) ) {
					if( attrDfltClusGrpName != null ) {
						throw new CFLibUniqueIndexViolationException( getClass(),
							S_ProcName,
							S_LocalName,
							attrLocalName );
					}
					attrDfltClusGrpName = attrs.getValue( idxAttr );
				}
				else if( attrLocalName.equals( "DfltTentGrpName" ) ) {
					if( attrDfltTentGrpName != null ) {
						throw new CFLibUniqueIndexViolationException( getClass(),
							S_ProcName,
							S_LocalName,
							attrLocalName );
					}
					attrDfltTentGrpName = attrs.getValue( idxAttr );
				}
				else if( attrLocalName.equals( "EMailAddress" ) ) {
					if( attrEMailAddress != null ) {
						throw new CFLibUniqueIndexViolationException( getClass(),
							S_ProcName,
							S_LocalName,
							attrLocalName );
					}
					attrEMailAddress = attrs.getValue( idxAttr );
				}
				else if( attrLocalName.equals( "EMConf" ) ) {
					if( attrEMConf != null ) {
						throw new CFLibUniqueIndexViolationException( getClass(),
							S_ProcName,
							S_LocalName,
							attrLocalName );
					}
					attrEMConf = attrs.getValue( idxAttr );
				}
				else if( attrLocalName.equals( "PWReset" ) ) {
					if( attrPWReset != null ) {
						throw new CFLibUniqueIndexViolationException( getClass(),
							S_ProcName,
							S_LocalName,
							attrLocalName );
					}
					attrPWReset = attrs.getValue( idxAttr );
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
			if( attrLoginId == null ) {
				throw new CFLibNullArgumentException( getClass(),
					S_ProcName,
					0,
					"LoginId" );
			}
			if( attrEMailAddress == null ) {
				throw new CFLibNullArgumentException( getClass(),
					S_ProcName,
					0,
					"EMailAddress" );
			}

			// Save named attributes to context
			CFLibXmlCoreContext curContext = getParser().getCurContext();
			curContext.putNamedValue( "Id", attrId );
			curContext.putNamedValue( "LoginId", attrLoginId );
			curContext.putNamedValue( "DfltSysGrpName", attrDfltSysGrpName );
			curContext.putNamedValue( "DfltClusGrpName", attrDfltClusGrpName );
			curContext.putNamedValue( "DfltTentGrpName", attrDfltTentGrpName );
			curContext.putNamedValue( "EMailAddress", attrEMailAddress );
			curContext.putNamedValue( "EMConf", attrEMConf );
			curContext.putNamedValue( "PWReset", attrPWReset );

			// Convert string attributes to native Java types
			// and apply the converted attributes to the editBuff.

			Integer natId;
			if( ( attrId != null ) && ( attrId.length() > 0 ) ) {
				natId = Integer.valueOf( Integer.parseInt( attrId ) );
			}
			else {
				natId = null;
			}
			String natLoginId = attrLoginId;
			editBuff.setRequiredLoginId( natLoginId );

			String natDfltSysGrpName = attrDfltSysGrpName;
			editBuff.setOptionalDfltSysGrpName( natDfltSysGrpName );

			String natDfltClusGrpName = attrDfltClusGrpName;
			editBuff.setOptionalDfltClusGrpName( natDfltClusGrpName );

			String natDfltTentGrpName = attrDfltTentGrpName;
			editBuff.setOptionalDfltTentGrpName( natDfltTentGrpName );

			String natEMailAddress = attrEMailAddress;
			editBuff.setRequiredEMailAddress( natEMailAddress );

			// Get the scope/container object

			CFLibXmlCoreContext parentContext = curContext.getPrevContext();
			Object scopeObj;
			if( parentContext != null ) {
				scopeObj = parentContext.getNamedValue( "Object" );
			}
			else {
				scopeObj = null;
			}

			CFSecSaxLoader.LoaderBehaviourEnum loaderBehaviour = saxLoader.getSecUserLoaderBehaviour();
			ICFSecSecUserEditObj editSecUser = null;
			ICFSecSecUserObj origSecUser = (ICFSecSecUserObj)schemaObj.getSecUserTableObj().readSecUserByULoginIdx( editBuff.getRequiredLoginId() );
			if( origSecUser == null ) {
				editSecUser = editBuff;
			}
			else {
				switch( loaderBehaviour ) {
					case Insert:
						break;
					case Update:
						editSecUser = (ICFSecSecUserEditObj)origSecUser.beginEdit();
						editSecUser.setRequiredLoginId( editBuff.getRequiredLoginId() );
						editSecUser.setOptionalDfltSysGrpName( editBuff.getOptionalDfltSysGrpName() );
						editSecUser.setOptionalDfltClusGrpName( editBuff.getOptionalDfltClusGrpName() );
						editSecUser.setOptionalDfltTentGrpName( editBuff.getOptionalDfltTentGrpName() );
						editSecUser.setRequiredEMailAddress( editBuff.getRequiredEMailAddress() );
						break;
					case Replace:
						editSecUser = (ICFSecSecUserEditObj)origSecUser.beginEdit();
						editSecUser.deleteInstance();
						editSecUser = null;
						origSecUser = null;
						editSecUser = editBuff;
						break;
				}
			}

			if( editSecUser != null ) {
				if( origSecUser != null ) {
					editSecUser.update();
				}
				else {
					origSecUser = (ICFSecSecUserObj)editSecUser.create();
				}
				editSecUser = null;
			}

			curContext.putNamedValue( "Object", origSecUser );
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
