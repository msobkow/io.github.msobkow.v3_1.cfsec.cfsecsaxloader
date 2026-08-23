
// Description: Java 25 XML SAX Element Handler for SecUserPWReset

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
 *	CFSecSaxLoaderSecUserPWResetParse XML SAX Element Handler implementation
 *	for SecUserPWReset.
 */
public class CFSecSaxLoaderSecUserPWReset
	extends CFLibXmlCoreElementHandler
{
	public CFSecSaxLoaderSecUserPWReset( CFSecSaxLoader saxLoader ) {
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
		ICFSecSecUserPWResetObj origBuff = null;
		ICFSecSecUserPWResetEditObj editBuff = null;
		// Common XML Attributes
		String attrId = null;
		// SecUserPWReset Attributes
		String attrSentToEMailAddr = null;
		String attrPasswordResetUuid6 = null;
		String attrNewAccount = null;
		// SecUserPWReset References
		ICFSecSecUserObj refUser = null;
		// Attribute Extraction
		String attrLocalName;
		int numAttrs;
		int idxAttr;
		final String S_LocalName = "LocalName";
		try {
			assert qName.equals( "SecUserPWReset" );

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
			origBuff = (ICFSecSecUserPWResetObj)schemaObj.getSecUserPWResetTableObj().newInstance();
			editBuff = (ICFSecSecUserPWResetEditObj)origBuff.beginEdit();

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
				else if( attrLocalName.equals( "SentToEMailAddr" ) ) {
					if( attrSentToEMailAddr != null ) {
						throw new CFLibUniqueIndexViolationException( getClass(),
							S_ProcName,
							S_LocalName,
							attrLocalName );
					}
					attrSentToEMailAddr = attrs.getValue( idxAttr );
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
				else if( attrLocalName.equals( "NewAccount" ) ) {
					if( attrNewAccount != null ) {
						throw new CFLibUniqueIndexViolationException( getClass(),
							S_ProcName,
							S_LocalName,
							attrLocalName );
					}
					attrNewAccount = attrs.getValue( idxAttr );
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
			if( attrSentToEMailAddr == null ) {
				throw new CFLibNullArgumentException( getClass(),
					S_ProcName,
					0,
					"SentToEMailAddr" );
			}
			if( ( attrPasswordResetUuid6 == null ) || ( attrPasswordResetUuid6.length() <= 0 ) ) {
				throw new CFLibNullArgumentException( getClass(),
					S_ProcName,
					0,
					"PasswordResetUuid6" );
			}
			if( ( attrNewAccount == null ) || ( attrNewAccount.length() <= 0 ) ) {
				throw new CFLibNullArgumentException( getClass(),
					S_ProcName,
					0,
					"NewAccount" );
			}

			// Save named attributes to context
			CFLibXmlCoreContext curContext = getParser().getCurContext();
			curContext.putNamedValue( "Id", attrId );
			curContext.putNamedValue( "SentToEMailAddr", attrSentToEMailAddr );
			curContext.putNamedValue( "PasswordResetUuid6", attrPasswordResetUuid6 );
			curContext.putNamedValue( "NewAccount", attrNewAccount );

			// Convert string attributes to native Java types
			// and apply the converted attributes to the editBuff.

			Integer natId;
			if( ( attrId != null ) && ( attrId.length() > 0 ) ) {
				natId = Integer.valueOf( Integer.parseInt( attrId ) );
			}
			else {
				natId = null;
			}
			String natSentToEMailAddr = attrSentToEMailAddr;
			editBuff.setRequiredSentToEMailAddr( natSentToEMailAddr );

			CFLibUuid6 natPasswordResetUuid6;
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
			editBuff.setRequiredPasswordResetUuid6( natPasswordResetUuid6 );

			boolean natNewAccount;
			if( attrNewAccount.equals( "true" ) || attrNewAccount.equals( "yes" ) || attrNewAccount.equals( "1" ) ) {
				natNewAccount = true;
			}
			else if( attrNewAccount.equals( "false" ) || attrNewAccount.equals( "no" ) || attrNewAccount.equals( "0" ) ) {
				natNewAccount = false;
			}
			else {
				throw new CFLibUsageException( getClass(),
					S_ProcName,
					String.format(Inz.x("cflib.xml.CFLibXmlUtil.XmlBooleanInvalid"), "NewAccount", attrNewAccount),
					String.format(Inz.s("cflib.xml.CFLibXmlUtil.XmlBooleanInvalid"), "NewAccount", attrNewAccount));
			}
			editBuff.setRequiredNewAccount( natNewAccount );

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
			else if( scopeObj instanceof ICFSecSecUserObj ) {
				refUser = (ICFSecSecUserObj) scopeObj;
				editBuff.setRequiredContainerUser( refUser );
			}
			else {
				throw new CFLibUnsupportedClassException( getClass(),
					S_ProcName,
					"scopeObj",
					scopeObj,
					"ICFSecSecUserObj" );
			}

			CFSecSaxLoader.LoaderBehaviourEnum loaderBehaviour = saxLoader.getSecUserPWResetLoaderBehaviour();
			ICFSecSecUserPWResetEditObj editSecUserPWReset = null;
			ICFSecSecUserPWResetObj origSecUserPWReset = (ICFSecSecUserPWResetObj)schemaObj.getSecUserPWResetTableObj().readSecUserPWResetByUUuid6Idx( editBuff.getRequiredPasswordResetUuid6() );
			if( origSecUserPWReset == null ) {
				editSecUserPWReset = editBuff;
			}
			else {
				switch( loaderBehaviour ) {
					case Insert:
						break;
					case Update:
						editSecUserPWReset = (ICFSecSecUserPWResetEditObj)origSecUserPWReset.beginEdit();
						editSecUserPWReset.setRequiredSentToEMailAddr( editBuff.getRequiredSentToEMailAddr() );
						editSecUserPWReset.setRequiredPasswordResetUuid6( editBuff.getRequiredPasswordResetUuid6() );
						editSecUserPWReset.setRequiredNewAccount( editBuff.getRequiredNewAccount() );
						break;
					case Replace:
						editSecUserPWReset = (ICFSecSecUserPWResetEditObj)origSecUserPWReset.beginEdit();
						editSecUserPWReset.deleteInstance();
						editSecUserPWReset = null;
						origSecUserPWReset = null;
						editSecUserPWReset = editBuff;
						break;
				}
			}

			if( editSecUserPWReset != null ) {
				if( origSecUserPWReset != null ) {
					editSecUserPWReset.update();
				}
				else {
					origSecUserPWReset = (ICFSecSecUserPWResetObj)editSecUserPWReset.create();
				}
				editSecUserPWReset = null;
			}

			curContext.putNamedValue( "Object", origSecUserPWReset );
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
