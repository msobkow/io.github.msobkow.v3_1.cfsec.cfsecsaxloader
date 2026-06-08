
// Description: Java 25 XML SAX Element Handler for TableInfo

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
 *	CFSecSaxLoaderTableInfoParse XML SAX Element Handler implementation
 *	for TableInfo.
 */
public class CFSecSaxLoaderTableInfo
	extends CFLibXmlCoreElementHandler
{
	public CFSecSaxLoaderTableInfo( CFSecSaxLoader saxLoader ) {
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
		ICFSecTableInfoObj origBuff = null;
		ICFSecTableInfoEditObj editBuff = null;
		// Common XML Attributes
		String attrId = null;
		// TableInfo Attributes
		String attrSchemaName = null;
		String attrTableName = null;
		String attrBackingClassCode = null;
		String attrRuntimeClassCode = null;
		String attrHasHistory = null;
		String attrIsMutable = null;
		String attrSecScopeName = null;
		String attrCodeVis = null;
		// TableInfo References
		// Attribute Extraction
		String attrLocalName;
		int numAttrs;
		int idxAttr;
		final String S_LocalName = "LocalName";
		try {
			assert qName.equals( "TableInfo" );

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
			origBuff = (ICFSecTableInfoObj)schemaObj.getTableInfoTableObj().newInstance();
			editBuff = (ICFSecTableInfoEditObj)origBuff.beginEdit();

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
				else if( attrLocalName.equals( "SchemaName" ) ) {
					if( attrSchemaName != null ) {
						throw new CFLibUniqueIndexViolationException( getClass(),
							S_ProcName,
							S_LocalName,
							attrLocalName );
					}
					attrSchemaName = attrs.getValue( idxAttr );
				}
				else if( attrLocalName.equals( "TableName" ) ) {
					if( attrTableName != null ) {
						throw new CFLibUniqueIndexViolationException( getClass(),
							S_ProcName,
							S_LocalName,
							attrLocalName );
					}
					attrTableName = attrs.getValue( idxAttr );
				}
				else if( attrLocalName.equals( "BackingClassCode" ) ) {
					if( attrBackingClassCode != null ) {
						throw new CFLibUniqueIndexViolationException( getClass(),
							S_ProcName,
							S_LocalName,
							attrLocalName );
					}
					attrBackingClassCode = attrs.getValue( idxAttr );
				}
				else if( attrLocalName.equals( "RuntimeClassCode" ) ) {
					if( attrRuntimeClassCode != null ) {
						throw new CFLibUniqueIndexViolationException( getClass(),
							S_ProcName,
							S_LocalName,
							attrLocalName );
					}
					attrRuntimeClassCode = attrs.getValue( idxAttr );
				}
				else if( attrLocalName.equals( "HasHistory" ) ) {
					if( attrHasHistory != null ) {
						throw new CFLibUniqueIndexViolationException( getClass(),
							S_ProcName,
							S_LocalName,
							attrLocalName );
					}
					attrHasHistory = attrs.getValue( idxAttr );
				}
				else if( attrLocalName.equals( "IsMutable" ) ) {
					if( attrIsMutable != null ) {
						throw new CFLibUniqueIndexViolationException( getClass(),
							S_ProcName,
							S_LocalName,
							attrLocalName );
					}
					attrIsMutable = attrs.getValue( idxAttr );
				}
				else if( attrLocalName.equals( "SecScopeName" ) ) {
					if( attrSecScopeName != null ) {
						throw new CFLibUniqueIndexViolationException( getClass(),
							S_ProcName,
							S_LocalName,
							attrLocalName );
					}
					attrSecScopeName = attrs.getValue( idxAttr );
				}
				else if( attrLocalName.equals( "CodeVis" ) ) {
					if( attrCodeVis != null ) {
						throw new CFLibUniqueIndexViolationException( getClass(),
							S_ProcName,
							S_LocalName,
							attrLocalName );
					}
					attrCodeVis = attrs.getValue( idxAttr );
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
			if( attrSchemaName == null ) {
				throw new CFLibNullArgumentException( getClass(),
					S_ProcName,
					0,
					"SchemaName" );
			}
			if( attrTableName == null ) {
				throw new CFLibNullArgumentException( getClass(),
					S_ProcName,
					0,
					"TableName" );
			}
			if( ( attrBackingClassCode == null ) || ( attrBackingClassCode.length() <= 0 ) ) {
				throw new CFLibNullArgumentException( getClass(),
					S_ProcName,
					0,
					"BackingClassCode" );
			}
			if( ( attrRuntimeClassCode == null ) || ( attrRuntimeClassCode.length() <= 0 ) ) {
				throw new CFLibNullArgumentException( getClass(),
					S_ProcName,
					0,
					"RuntimeClassCode" );
			}
			if( ( attrHasHistory == null ) || ( attrHasHistory.length() <= 0 ) ) {
				throw new CFLibNullArgumentException( getClass(),
					S_ProcName,
					0,
					"HasHistory" );
			}
			if( ( attrIsMutable == null ) || ( attrIsMutable.length() <= 0 ) ) {
				throw new CFLibNullArgumentException( getClass(),
					S_ProcName,
					0,
					"IsMutable" );
			}
			if( attrSecScopeName == null ) {
				throw new CFLibNullArgumentException( getClass(),
					S_ProcName,
					0,
					"SecScopeName" );
			}
			if( attrCodeVis == null ) {
				throw new CFLibNullArgumentException( getClass(),
					S_ProcName,
					0,
					"CodeVis" );
			}

			// Save named attributes to context
			CFLibXmlCoreContext curContext = getParser().getCurContext();
			curContext.putNamedValue( "Id", attrId );
			curContext.putNamedValue( "SchemaName", attrSchemaName );
			curContext.putNamedValue( "TableName", attrTableName );
			curContext.putNamedValue( "BackingClassCode", attrBackingClassCode );
			curContext.putNamedValue( "RuntimeClassCode", attrRuntimeClassCode );
			curContext.putNamedValue( "HasHistory", attrHasHistory );
			curContext.putNamedValue( "IsMutable", attrIsMutable );
			curContext.putNamedValue( "SecScopeName", attrSecScopeName );
			curContext.putNamedValue( "CodeVis", attrCodeVis );

			// Convert string attributes to native Java types
			// and apply the converted attributes to the editBuff.

			Integer natId;
			if( ( attrId != null ) && ( attrId.length() > 0 ) ) {
				natId = Integer.valueOf( Integer.parseInt( attrId ) );
			}
			else {
				natId = null;
			}
			String natSchemaName = attrSchemaName;
			editBuff.setRequiredSchemaName( natSchemaName );

			String natTableName = attrTableName;
			editBuff.setRequiredTableName( natTableName );

			int natBackingClassCode = Integer.parseInt( attrBackingClassCode );
			editBuff.setRequiredBackingClassCode( natBackingClassCode );

			int natRuntimeClassCode = Integer.parseInt( attrRuntimeClassCode );
			editBuff.setRequiredRuntimeClassCode( natRuntimeClassCode );

			boolean natHasHistory;
			if( attrHasHistory.equals( "true" ) || attrHasHistory.equals( "yes" ) || attrHasHistory.equals( "1" ) ) {
				natHasHistory = true;
			}
			else if( attrHasHistory.equals( "false" ) || attrHasHistory.equals( "no" ) || attrHasHistory.equals( "0" ) ) {
				natHasHistory = false;
			}
			else {
				throw new CFLibUsageException( getClass(),
					S_ProcName,
					String.format(Inz.x("cflib.xml.CFLibXmlUtil.XmlBooleanInvalid"), "HasHistory", attrHasHistory),
					String.format(Inz.s("cflib.xml.CFLibXmlUtil.XmlBooleanInvalid"), "HasHistory", attrHasHistory));
			}
			editBuff.setRequiredHasHistory( natHasHistory );

			boolean natIsMutable;
			if( attrIsMutable.equals( "true" ) || attrIsMutable.equals( "yes" ) || attrIsMutable.equals( "1" ) ) {
				natIsMutable = true;
			}
			else if( attrIsMutable.equals( "false" ) || attrIsMutable.equals( "no" ) || attrIsMutable.equals( "0" ) ) {
				natIsMutable = false;
			}
			else {
				throw new CFLibUsageException( getClass(),
					S_ProcName,
					String.format(Inz.x("cflib.xml.CFLibXmlUtil.XmlBooleanInvalid"), "IsMutable", attrIsMutable),
					String.format(Inz.s("cflib.xml.CFLibXmlUtil.XmlBooleanInvalid"), "IsMutable", attrIsMutable));
			}
			editBuff.setRequiredIsMutable( natIsMutable );

			String natSecScopeName = attrSecScopeName;
			editBuff.setRequiredSecScopeName( natSecScopeName );

			String natCodeVis = attrCodeVis;
			editBuff.setRequiredCodeVis( natCodeVis );

			// Get the scope/container object

			CFLibXmlCoreContext parentContext = curContext.getPrevContext();
			Object scopeObj;
			if( parentContext != null ) {
				scopeObj = parentContext.getNamedValue( "Object" );
			}
			else {
				scopeObj = null;
			}

			CFSecSaxLoader.LoaderBehaviourEnum loaderBehaviour = saxLoader.getTableInfoLoaderBehaviour();
			ICFSecTableInfoEditObj editTableInfo = null;
			ICFSecTableInfoObj origTableInfo = (ICFSecTableInfoObj)schemaObj.getTableInfoTableObj().readTableInfoByTableNameIdx( editBuff.getRequiredTableName() );
			if( origTableInfo == null ) {
				editTableInfo = editBuff;
			}
			else {
				switch( loaderBehaviour ) {
					case Insert:
						break;
					case Update:
						editTableInfo = (ICFSecTableInfoEditObj)origTableInfo.beginEdit();
						editTableInfo.setRequiredSchemaName( editBuff.getRequiredSchemaName() );
						editTableInfo.setRequiredTableName( editBuff.getRequiredTableName() );
						editTableInfo.setRequiredBackingClassCode( editBuff.getRequiredBackingClassCode() );
						editTableInfo.setRequiredRuntimeClassCode( editBuff.getRequiredRuntimeClassCode() );
						editTableInfo.setRequiredHasHistory( editBuff.getRequiredHasHistory() );
						editTableInfo.setRequiredIsMutable( editBuff.getRequiredIsMutable() );
						editTableInfo.setRequiredSecScopeName( editBuff.getRequiredSecScopeName() );
						editTableInfo.setRequiredCodeVis( editBuff.getRequiredCodeVis() );
						break;
					case Replace:
						editTableInfo = (ICFSecTableInfoEditObj)origTableInfo.beginEdit();
						editTableInfo.deleteInstance();
						editTableInfo = null;
						origTableInfo = null;
						editTableInfo = editBuff;
						break;
				}
			}

			if( editTableInfo != null ) {
				if( origTableInfo != null ) {
					editTableInfo.update();
				}
				else {
					origTableInfo = (ICFSecTableInfoObj)editTableInfo.create();
				}
				editTableInfo = null;
			}

			curContext.putNamedValue( "Object", origTableInfo );
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
