
// Description: Java 25 XML SAX Element Handler for SecUser

/*
 *	io.github.msobkow.CFSec
 *
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow
 *	
 *	Mark's Code Fractal 3.1 CFSec - Security Services
 *	
 *	This file is part of Mark's Code Fractal CFSec.
 *	
 *	Mark's Code Fractal CFSec is available under dual commercial license from
 *	Mark Stephen Sobkow, or under the terms of the GNU Library General Public License,
 *	Version 3 or later.
 *	
 *	Mark's Code Fractal CFSec is free software: you can redistribute it and/or
 *	modify it under the terms of the GNU Library General Public License as published by
 *	the Free Software Foundation, either version 3 of the License, or
 *	(at your option) any later version.
 *	
 *	Mark's Code Fractal CFSec is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *	
 *	You should have received a copy of the GNU Library General Public License
 *	along with Mark's Code Fractal CFSec.  If not, see <https://www.gnu.org/licenses/>.
 *	
 *	If you wish to modify and use this code without publishing your changes in order to
 *	tie it to proprietary code, please contact Mark Stephen Sobkow
 *	for a commercial license at mark.sobkow@gmail.com
 *	
 */

package io.github.msobkow.v3_1.cfsec.cfsecsaxloader;

import java.math.*;
import java.sql.*;
import java.text.*;
import java.time.*;
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import org.xml.sax.*;
import io.github.msobkow.v3_1.cflib.*;
import io.github.msobkow.v3_1.cflib.dbutil.*;
import io.github.msobkow.v3_1.cflib.inz.Inz;
import io.github.msobkow.v3_1.cflib.xml.*;
import io.github.msobkow.v3_1.cfsec.cfsec.*;
import io.github.msobkow.v3_1.cfsec.cfsecobj.*;

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
		String attrEMailAddress = null;
		String attrEMailConfirmUuid6 = null;
		String attrPasswordHash = null;
		String attrPasswordResetUuid6 = null;
		String attrDefDev = null;
		// SecUser References
		ICFSecSecDeviceObj refDefDev = null;
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
				else if( attrLocalName.equals( "EMailAddress" ) ) {
					if( attrEMailAddress != null ) {
						throw new CFLibUniqueIndexViolationException( getClass(),
							S_ProcName,
							S_LocalName,
							attrLocalName );
					}
					attrEMailAddress = attrs.getValue( idxAttr );
				}
				else if( attrLocalName.equals( "EMailConfirmUuid6" ) ) {
					if( attrEMailConfirmUuid6 != null ) {
						throw new CFLibUniqueIndexViolationException( getClass(),
							S_ProcName,
							S_LocalName,
							attrLocalName );
					}
					attrEMailConfirmUuid6 = attrs.getValue( idxAttr );
				}
				else if( attrLocalName.equals( "PasswordHash" ) ) {
					if( attrPasswordHash != null ) {
						throw new CFLibUniqueIndexViolationException( getClass(),
							S_ProcName,
							S_LocalName,
							attrLocalName );
					}
					attrPasswordHash = attrs.getValue( idxAttr );
				}
				else if( attrLocalName.equals( "PasswordResetUuid6" ) ) {
					if( attrPasswordResetUuid6 != null ) {
						throw new CFLibUniqueIndexViolationException( getClass(),
							S_ProcName,
							S_LocalName,
							attrLocalName );
					}
					attrPasswordResetUuid6 = attrs.getValue( idxAttr );
				}
				else if( attrLocalName.equals( "DefDev" ) ) {
					if( attrDefDev != null ) {
						throw new CFLibUniqueIndexViolationException( getClass(),
							S_ProcName,
							S_LocalName,
							attrLocalName );
					}
					attrDefDev = attrs.getValue( idxAttr );
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
			if( attrPasswordHash == null ) {
				throw new CFLibNullArgumentException( getClass(),
					S_ProcName,
					0,
					"PasswordHash" );
			}

			// Save named attributes to context
			CFLibXmlCoreContext curContext = getParser().getCurContext();
			curContext.putNamedValue( "Id", attrId );
			curContext.putNamedValue( "LoginId", attrLoginId );
			curContext.putNamedValue( "EMailAddress", attrEMailAddress );
			curContext.putNamedValue( "EMailConfirmUuid6", attrEMailConfirmUuid6 );
			curContext.putNamedValue( "PasswordHash", attrPasswordHash );
			curContext.putNamedValue( "PasswordResetUuid6", attrPasswordResetUuid6 );
			curContext.putNamedValue( "DefDev", attrDefDev );

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

			String natEMailAddress = attrEMailAddress;
			editBuff.setRequiredEMailAddress( natEMailAddress );

			CFLibUuid6 natEMailConfirmUuid6;
			if( ( attrEMailConfirmUuid6 == null ) || ( attrEMailConfirmUuid6.length() <= 0 ) ) {
				natEMailConfirmUuid6 = null;
			}
			else {
				try {
					natEMailConfirmUuid6 = CFLibUuid6.fromString( attrEMailConfirmUuid6 );
				}
				catch( RuntimeException e ) {
					throw new CFLibInvalidArgumentException( getClass(),
						S_ProcName,
						0,
						"EMailConfirmUuid6",
						e );
				}
			}
			editBuff.setOptionalEMailConfirmUuid6( natEMailConfirmUuid6 );

			String natPasswordHash = attrPasswordHash;
			editBuff.setRequiredPasswordHash( natPasswordHash );

			CFLibUuid6 natPasswordResetUuid6;
			if( ( attrPasswordResetUuid6 == null ) || ( attrPasswordResetUuid6.length() <= 0 ) ) {
				natPasswordResetUuid6 = null;
			}
			else {
				try {
					natPasswordResetUuid6 = CFLibUuid6.fromString( attrPasswordResetUuid6 );
				}
				catch( RuntimeException e ) {
					throw new CFLibInvalidArgumentException( getClass(),
						S_ProcName,
						0,
						"PasswordResetUuid6",
						e );
				}
			}
			editBuff.setOptionalPasswordResetUuid6( natPasswordResetUuid6 );

			// Get the scope/container object

			CFLibXmlCoreContext parentContext = curContext.getPrevContext();
			Object scopeObj;
			if( parentContext != null ) {
				scopeObj = parentContext.getNamedValue( "Object" );
			}
			else {
				scopeObj = null;
			}

			// Lookup refDefDev by key name value attr
			if( ( attrDefDev != null ) && ( attrDefDev.length() > 0 ) ) {
				refDefDev = (ICFSecSecDeviceObj)schemaObj.getSecDeviceTableObj().readSecDeviceByNameIdx( editBuff.getOptionalDfltDevUserId(),
				attrDefDev );
				if( refDefDev == null ) {
					throw new CFLibNullArgumentException( getClass(),
						S_ProcName,
						0,
						"Resolve DefDev reference named \"" + attrDefDev + "\" to table SecDevice" );
				}
			}
			else {
				refDefDev = null;
			}
			editBuff.setOptionalLookupDefDev( refDefDev );

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
						editSecUser.setRequiredEMailAddress( editBuff.getRequiredEMailAddress() );
						editSecUser.setOptionalEMailConfirmUuid6( editBuff.getOptionalEMailConfirmUuid6() );
						editSecUser.setRequiredPasswordHash( editBuff.getRequiredPasswordHash() );
						editSecUser.setOptionalPasswordResetUuid6( editBuff.getOptionalPasswordResetUuid6() );
						editSecUser.setOptionalLookupDefDev( editBuff.getOptionalLookupDefDev() );
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
