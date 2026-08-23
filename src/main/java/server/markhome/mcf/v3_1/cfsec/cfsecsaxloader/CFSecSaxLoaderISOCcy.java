
// Description: Java 25 XML SAX Element Handler for ISOCcy

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
 *	CFSecSaxLoaderISOCcyParse XML SAX Element Handler implementation
 *	for ISOCcy.
 */
public class CFSecSaxLoaderISOCcy
	extends CFLibXmlCoreElementHandler
{
	public CFSecSaxLoaderISOCcy( CFSecSaxLoader saxLoader ) {
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
		ICFSecISOCcyObj origBuff = null;
		ICFSecISOCcyEditObj editBuff = null;
		// Common XML Attributes
		String attrId = null;
		// ISOCcy Attributes
		String attrISOCode = null;
		String attrName = null;
		String attrUnitSymbol = null;
		String attrPrecis = null;
		// ISOCcy References
		// Attribute Extraction
		String attrLocalName;
		int numAttrs;
		int idxAttr;
		final String S_LocalName = "LocalName";
		try {
			assert qName.equals( "ISOCcy" );

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
			origBuff = (ICFSecISOCcyObj)schemaObj.getISOCcyTableObj().newInstance();
			editBuff = (ICFSecISOCcyEditObj)origBuff.beginEdit();

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
				else if( attrLocalName.equals( "ISOCode" ) ) {
					if( attrISOCode != null ) {
						throw new CFLibUniqueIndexViolationException( getClass(),
							S_ProcName,
							S_LocalName,
							attrLocalName );
					}
					attrISOCode = attrs.getValue( idxAttr );
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
				else if( attrLocalName.equals( "UnitSymbol" ) ) {
					if( attrUnitSymbol != null ) {
						throw new CFLibUniqueIndexViolationException( getClass(),
							S_ProcName,
							S_LocalName,
							attrLocalName );
					}
					attrUnitSymbol = attrs.getValue( idxAttr );
				}
				else if( attrLocalName.equals( "Precis" ) ) {
					if( attrPrecis != null ) {
						throw new CFLibUniqueIndexViolationException( getClass(),
							S_ProcName,
							S_LocalName,
							attrLocalName );
					}
					attrPrecis = attrs.getValue( idxAttr );
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
			if( attrISOCode == null ) {
				throw new CFLibNullArgumentException( getClass(),
					S_ProcName,
					0,
					"ISOCode" );
			}
			if( attrName == null ) {
				throw new CFLibNullArgumentException( getClass(),
					S_ProcName,
					0,
					"Name" );
			}
			if( ( attrPrecis == null ) || ( attrPrecis.length() <= 0 ) ) {
				throw new CFLibNullArgumentException( getClass(),
					S_ProcName,
					0,
					"Precis" );
			}

			// Save named attributes to context
			CFLibXmlCoreContext curContext = getParser().getCurContext();
			curContext.putNamedValue( "Id", attrId );
			curContext.putNamedValue( "ISOCode", attrISOCode );
			curContext.putNamedValue( "Name", attrName );
			curContext.putNamedValue( "UnitSymbol", attrUnitSymbol );
			curContext.putNamedValue( "Precis", attrPrecis );

			// Convert string attributes to native Java types
			// and apply the converted attributes to the editBuff.

			Integer natId;
			if( ( attrId != null ) && ( attrId.length() > 0 ) ) {
				natId = Integer.valueOf( Integer.parseInt( attrId ) );
			}
			else {
				natId = null;
			}
			String natISOCode = attrISOCode;
			editBuff.setRequiredISOCode( natISOCode );

			String natName = attrName;
			editBuff.setRequiredName( natName );

			String natUnitSymbol = attrUnitSymbol;
			editBuff.setOptionalUnitSymbol( natUnitSymbol );

			short natPrecis = Short.parseShort( attrPrecis );
			editBuff.setRequiredPrecis( natPrecis );

			// Get the scope/container object

			CFLibXmlCoreContext parentContext = curContext.getPrevContext();
			Object scopeObj;
			if( parentContext != null ) {
				scopeObj = parentContext.getNamedValue( "Object" );
			}
			else {
				scopeObj = null;
			}

			CFSecSaxLoader.LoaderBehaviourEnum loaderBehaviour = saxLoader.getISOCcyLoaderBehaviour();
			ICFSecISOCcyEditObj editISOCcy = null;
			ICFSecISOCcyObj origISOCcy = (ICFSecISOCcyObj)schemaObj.getISOCcyTableObj().readISOCcyByCcyCdIdx( editBuff.getRequiredISOCode() );
			if( origISOCcy == null ) {
				editISOCcy = editBuff;
			}
			else {
				switch( loaderBehaviour ) {
					case Insert:
						break;
					case Update:
						editISOCcy = (ICFSecISOCcyEditObj)origISOCcy.beginEdit();
						editISOCcy.setRequiredISOCode( editBuff.getRequiredISOCode() );
						editISOCcy.setRequiredName( editBuff.getRequiredName() );
						editISOCcy.setOptionalUnitSymbol( editBuff.getOptionalUnitSymbol() );
						editISOCcy.setRequiredPrecis( editBuff.getRequiredPrecis() );
						break;
					case Replace:
						editISOCcy = (ICFSecISOCcyEditObj)origISOCcy.beginEdit();
						editISOCcy.deleteInstance();
						editISOCcy = null;
						origISOCcy = null;
						editISOCcy = editBuff;
						break;
				}
			}

			if( editISOCcy != null ) {
				if( origISOCcy != null ) {
					editISOCcy.update();
				}
				else {
					origISOCcy = (ICFSecISOCcyObj)editISOCcy.create();
				}
				editISOCcy = null;
			}

			curContext.putNamedValue( "Object", origISOCcy );
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
