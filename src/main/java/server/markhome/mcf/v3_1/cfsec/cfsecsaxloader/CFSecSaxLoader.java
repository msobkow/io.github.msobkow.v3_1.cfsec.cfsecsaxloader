// Description: Java 25 XML SAX Parser for CFSec.

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

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.lang.reflect.*;
import java.math.*;
import java.net.URISyntaxException;
import java.net.URL;
import java.sql.*;
import java.text.*;
import java.util.*;
import javax.naming.*;
import javax.sql.*;
import org.apache.commons.codec.binary.Base64;
import org.xml.sax.*;

import server.markhome.mcf.v3_1.cflib.*;
import server.markhome.mcf.v3_1.cflib.xml.*;
import server.markhome.mcf.v3_1.cfsec.cfsec.*;
import server.markhome.mcf.v3_1.cfsec.cfsecobj.*;

public class CFSecSaxLoader
	extends CFLibXmlCoreSaxParser
	implements ContentHandler
{

	// The namespace URI of the supported schema
	public final static String	SCHEMA_XMLNS = "http://mcf.markhome.server/mcf/v3_1/xsd/cfsec-structured.xsd";

	// The source for loading the supported schema
	public final static String	SCHEMA_URI = "http://mcf.markhome.server/mcf/v3_1/xsd/cfsec-structured.xsd";
	public final static String	SCHEMA_ROOT_URI = "http://mcf.markhome.server/mcf/v3_1/xsd/cfsec-structured.xsd";

	// The schema instance to load in to

	private ICFSecSchemaObj schemaObj = null;

	// The cluster to use for loading

	private ICFSecClusterObj useCluster = null;

	public ICFSecClusterObj getUseCluster() {
		return( useCluster );
	}

	public void setUseCluster( ICFSecClusterObj value ) {
		useCluster = value;
	}

	// The tenant to use for loading

	private ICFSecTenantObj useTenant = null;

	public ICFSecTenantObj getUseTenant() {
		return( useTenant );
	}

	public void setUseTenant( ICFSecTenantObj value ) {
		useTenant = value;
	}

	// Loader behaviour configuration attributes

	public enum LoaderBehaviourEnum {
		Insert,
		Update,
		Replace
	};
	private LoaderBehaviourEnum clusterLoaderBehaviour = LoaderBehaviourEnum.Insert;
	private LoaderBehaviourEnum iSOCcyLoaderBehaviour = LoaderBehaviourEnum.Update;
	private LoaderBehaviourEnum iSOCtryLoaderBehaviour = LoaderBehaviourEnum.Update;
	private LoaderBehaviourEnum iSOCtryCcyLoaderBehaviour = LoaderBehaviourEnum.Insert;
	private LoaderBehaviourEnum iSOCtryLangLoaderBehaviour = LoaderBehaviourEnum.Insert;
	private LoaderBehaviourEnum iSOLangLoaderBehaviour = LoaderBehaviourEnum.Update;
	private LoaderBehaviourEnum iSOTZoneLoaderBehaviour = LoaderBehaviourEnum.Update;
	private LoaderBehaviourEnum secClusGrpLoaderBehaviour = LoaderBehaviourEnum.Insert;
	private LoaderBehaviourEnum secClusGrpIncLoaderBehaviour = LoaderBehaviourEnum.Insert;
	private LoaderBehaviourEnum secClusGrpMembLoaderBehaviour = LoaderBehaviourEnum.Insert;
	private LoaderBehaviourEnum secSessionLoaderBehaviour = LoaderBehaviourEnum.Insert;
	private LoaderBehaviourEnum secSysGrpLoaderBehaviour = LoaderBehaviourEnum.Insert;
	private LoaderBehaviourEnum secSysGrpIncLoaderBehaviour = LoaderBehaviourEnum.Insert;
	private LoaderBehaviourEnum secSysGrpMembLoaderBehaviour = LoaderBehaviourEnum.Insert;
	private LoaderBehaviourEnum secTentGrpLoaderBehaviour = LoaderBehaviourEnum.Insert;
	private LoaderBehaviourEnum secTentGrpIncLoaderBehaviour = LoaderBehaviourEnum.Insert;
	private LoaderBehaviourEnum secTentGrpMembLoaderBehaviour = LoaderBehaviourEnum.Insert;
	private LoaderBehaviourEnum secUserLoaderBehaviour = LoaderBehaviourEnum.Insert;
	private LoaderBehaviourEnum secUserPWHistoryLoaderBehaviour = LoaderBehaviourEnum.Insert;
	private LoaderBehaviourEnum secUserPasswordLoaderBehaviour = LoaderBehaviourEnum.Insert;
	private LoaderBehaviourEnum sysClusterLoaderBehaviour = LoaderBehaviourEnum.Insert;
	private LoaderBehaviourEnum tenantLoaderBehaviour = LoaderBehaviourEnum.Insert;


	// Constructors

	public CFSecSaxLoader() {
		super();
		setRootElementHandler( getSaxRootHandler() );
		initParser();
	}

	public CFSecSaxLoader( ICFLibMessageLog logger ) {
		super( logger );
		setRootElementHandler( getSaxRootHandler() );
		initParser();
	}

	// Element Handler instances

	private CFSecSaxLoaderCluster clusterHandler = null;
	private CFSecSaxLoaderISOCcy iSOCcyHandler = null;
	private CFSecSaxLoaderISOCtry iSOCtryHandler = null;
	private CFSecSaxLoaderISOCtryCcy iSOCtryCcyHandler = null;
	private CFSecSaxLoaderISOCtryLang iSOCtryLangHandler = null;
	private CFSecSaxLoaderISOLang iSOLangHandler = null;
	private CFSecSaxLoaderISOTZone iSOTZoneHandler = null;
	private CFSecSaxLoaderSecClusGrp secClusGrpHandler = null;
	private CFSecSaxLoaderSecClusGrpInc secClusGrpIncHandler = null;
	private CFSecSaxLoaderSecClusGrpMemb secClusGrpMembHandler = null;
	private CFSecSaxLoaderSecSession secSessionHandler = null;
	private CFSecSaxLoaderSecSysGrp secSysGrpHandler = null;
	private CFSecSaxLoaderSecSysGrpInc secSysGrpIncHandler = null;
	private CFSecSaxLoaderSecSysGrpMemb secSysGrpMembHandler = null;
	private CFSecSaxLoaderSecTentGrp secTentGrpHandler = null;
	private CFSecSaxLoaderSecTentGrpInc secTentGrpIncHandler = null;
	private CFSecSaxLoaderSecTentGrpMemb secTentGrpMembHandler = null;
	private CFSecSaxLoaderSecUser secUserHandler = null;
	private CFSecSaxLoaderSecUserPWHistory secUserPWHistoryHandler = null;
	private CFSecSaxLoaderSecUserPassword secUserPasswordHandler = null;
	private CFSecSaxLoaderSysCluster sysClusterHandler = null;
	private CFSecSaxLoaderTenant tenantHandler = null;
	private CFSecSaxRootHandler saxRootHandler = null;

	private CFSecSaxDocHandler saxDocHandler = null;

	// Schema object accessors

	// SchemaObj accessors

	public ICFSecSchemaObj getSchemaObj() {
		return( schemaObj );
	}

	public void setSchemaObj( ICFSecSchemaObj value ) {
		schemaObj = value;
	}

	// Element Handler Resolver Factories

	protected CFSecSaxLoaderCluster getClusterHandler() {
		if( clusterHandler == null ) {
			clusterHandler = new CFSecSaxLoaderCluster( this );
			clusterHandler.addElementHandler( "Tenant", getTenantHandler() );
			clusterHandler.addElementHandler( "SysCluster", getSysClusterHandler() );
		}
		return( clusterHandler );
	}
	protected CFSecSaxLoaderISOCcy getISOCcyHandler() {
		if( iSOCcyHandler == null ) {
			iSOCcyHandler = new CFSecSaxLoaderISOCcy( this );
		}
		return( iSOCcyHandler );
	}
	protected CFSecSaxLoaderISOCtry getISOCtryHandler() {
		if( iSOCtryHandler == null ) {
			iSOCtryHandler = new CFSecSaxLoaderISOCtry( this );
			iSOCtryHandler.addElementHandler( "ISOCtryCcy", getISOCtryCcyHandler() );
			iSOCtryHandler.addElementHandler( "ISOCtryLang", getISOCtryLangHandler() );
		}
		return( iSOCtryHandler );
	}
	protected CFSecSaxLoaderISOCtryCcy getISOCtryCcyHandler() {
		if( iSOCtryCcyHandler == null ) {
			iSOCtryCcyHandler = new CFSecSaxLoaderISOCtryCcy( this );
		}
		return( iSOCtryCcyHandler );
	}
	protected CFSecSaxLoaderISOCtryLang getISOCtryLangHandler() {
		if( iSOCtryLangHandler == null ) {
			iSOCtryLangHandler = new CFSecSaxLoaderISOCtryLang( this );
		}
		return( iSOCtryLangHandler );
	}
	protected CFSecSaxLoaderISOLang getISOLangHandler() {
		if( iSOLangHandler == null ) {
			iSOLangHandler = new CFSecSaxLoaderISOLang( this );
		}
		return( iSOLangHandler );
	}
	protected CFSecSaxLoaderISOTZone getISOTZoneHandler() {
		if( iSOTZoneHandler == null ) {
			iSOTZoneHandler = new CFSecSaxLoaderISOTZone( this );
		}
		return( iSOTZoneHandler );
	}
	protected CFSecSaxLoaderSecClusGrp getSecClusGrpHandler() {
		if( secClusGrpHandler == null ) {
			secClusGrpHandler = new CFSecSaxLoaderSecClusGrp( this );
		}
		return( secClusGrpHandler );
	}
	protected CFSecSaxLoaderSecClusGrpInc getSecClusGrpIncHandler() {
		if( secClusGrpIncHandler == null ) {
			secClusGrpIncHandler = new CFSecSaxLoaderSecClusGrpInc( this );
		}
		return( secClusGrpIncHandler );
	}
	protected CFSecSaxLoaderSecClusGrpMemb getSecClusGrpMembHandler() {
		if( secClusGrpMembHandler == null ) {
			secClusGrpMembHandler = new CFSecSaxLoaderSecClusGrpMemb( this );
		}
		return( secClusGrpMembHandler );
	}
	protected CFSecSaxLoaderSecSession getSecSessionHandler() {
		if( secSessionHandler == null ) {
			secSessionHandler = new CFSecSaxLoaderSecSession( this );
		}
		return( secSessionHandler );
	}
	protected CFSecSaxLoaderSecSysGrp getSecSysGrpHandler() {
		if( secSysGrpHandler == null ) {
			secSysGrpHandler = new CFSecSaxLoaderSecSysGrp( this );
		}
		return( secSysGrpHandler );
	}
	protected CFSecSaxLoaderSecSysGrpInc getSecSysGrpIncHandler() {
		if( secSysGrpIncHandler == null ) {
			secSysGrpIncHandler = new CFSecSaxLoaderSecSysGrpInc( this );
		}
		return( secSysGrpIncHandler );
	}
	protected CFSecSaxLoaderSecSysGrpMemb getSecSysGrpMembHandler() {
		if( secSysGrpMembHandler == null ) {
			secSysGrpMembHandler = new CFSecSaxLoaderSecSysGrpMemb( this );
		}
		return( secSysGrpMembHandler );
	}
	protected CFSecSaxLoaderSecTentGrp getSecTentGrpHandler() {
		if( secTentGrpHandler == null ) {
			secTentGrpHandler = new CFSecSaxLoaderSecTentGrp( this );
		}
		return( secTentGrpHandler );
	}
	protected CFSecSaxLoaderSecTentGrpInc getSecTentGrpIncHandler() {
		if( secTentGrpIncHandler == null ) {
			secTentGrpIncHandler = new CFSecSaxLoaderSecTentGrpInc( this );
		}
		return( secTentGrpIncHandler );
	}
	protected CFSecSaxLoaderSecTentGrpMemb getSecTentGrpMembHandler() {
		if( secTentGrpMembHandler == null ) {
			secTentGrpMembHandler = new CFSecSaxLoaderSecTentGrpMemb( this );
		}
		return( secTentGrpMembHandler );
	}
	protected CFSecSaxLoaderSecUser getSecUserHandler() {
		if( secUserHandler == null ) {
			secUserHandler = new CFSecSaxLoaderSecUser( this );
		}
		return( secUserHandler );
	}
	protected CFSecSaxLoaderSecUserPWHistory getSecUserPWHistoryHandler() {
		if( secUserPWHistoryHandler == null ) {
			secUserPWHistoryHandler = new CFSecSaxLoaderSecUserPWHistory( this );
		}
		return( secUserPWHistoryHandler );
	}
	protected CFSecSaxLoaderSecUserPassword getSecUserPasswordHandler() {
		if( secUserPasswordHandler == null ) {
			secUserPasswordHandler = new CFSecSaxLoaderSecUserPassword( this );
		}
		return( secUserPasswordHandler );
	}
	protected CFSecSaxLoaderSysCluster getSysClusterHandler() {
		if( sysClusterHandler == null ) {
			sysClusterHandler = new CFSecSaxLoaderSysCluster( this );
		}
		return( sysClusterHandler );
	}
	protected CFSecSaxLoaderTenant getTenantHandler() {
		if( tenantHandler == null ) {
			tenantHandler = new CFSecSaxLoaderTenant( this );
		}
		return( tenantHandler );
	}
	// Root Element Handler Resolver Factory

	protected CFSecSaxRootHandler getSaxRootHandler() {
		if( saxRootHandler == null ) {
			saxRootHandler = new CFSecSaxRootHandler( this );
			saxRootHandler.addElementHandler( "CFSec", getSaxDocHandler() );
		}
		return( saxRootHandler );
	}

	// Root Element Handler

	/*
	 *	CFSecSaxRootHandler XML SAX Root Element Handler implementation
	 */
	public class CFSecSaxRootHandler
		extends CFLibXmlCoreElementHandler
	{
		public CFSecSaxRootHandler( CFSecSaxLoader saxLoader ) {
			super( saxLoader );
		}

		public void startElement(
			String		uri,
			String		localName,
			String		qName,
			Attributes	attrs )
		throws SAXException
		{
		}

		public void endElement(
			String		uri,
			String		localName,
			String		qName )
		throws SAXException
		{
		}
	}

	// Document Element Handler Resolver Factory

	protected CFSecSaxDocHandler getSaxDocHandler() {
		if( saxDocHandler == null ) {
			saxDocHandler = new CFSecSaxDocHandler( this );
			saxDocHandler.addElementHandler( "Cluster", getClusterHandler() );
			saxDocHandler.addElementHandler( "ISOCcy", getISOCcyHandler() );
			saxDocHandler.addElementHandler( "ISOCtry", getISOCtryHandler() );
			saxDocHandler.addElementHandler( "ISOLang", getISOLangHandler() );
			saxDocHandler.addElementHandler( "ISOTZone", getISOTZoneHandler() );
			saxDocHandler.addElementHandler( "SecClusGrp", getSecClusGrpHandler() );
			saxDocHandler.addElementHandler( "SecClusGrpInc", getSecClusGrpIncHandler() );
			saxDocHandler.addElementHandler( "SecClusGrpMemb", getSecClusGrpMembHandler() );
			saxDocHandler.addElementHandler( "SecSession", getSecSessionHandler() );
			saxDocHandler.addElementHandler( "SecSysGrp", getSecSysGrpHandler() );
			saxDocHandler.addElementHandler( "SecTentGrp", getSecTentGrpHandler() );
			saxDocHandler.addElementHandler( "SecTentGrpInc", getSecTentGrpIncHandler() );
			saxDocHandler.addElementHandler( "SecTentGrpMemb", getSecTentGrpMembHandler() );
			saxDocHandler.addElementHandler( "SecUser", getSecUserHandler() );
			saxDocHandler.addElementHandler( "SecUserPWHistory", getSecUserPWHistoryHandler() );
			saxDocHandler.addElementHandler( "SecUserPassword", getSecUserPasswordHandler() );
		}
		return( saxDocHandler );
	}

	// Document Element Handler

	/*
	 *	CFSecSaxDocHandler XML SAX Doc Element Handler implementation
	 */
	public class CFSecSaxDocHandler
		extends CFLibXmlCoreElementHandler
	{
		public CFSecSaxDocHandler( CFSecSaxLoader saxLoader ) {
			super( saxLoader );
		}

		public void startElement(
			String		uri,
			String		localName,
			String		qName,
			Attributes	attrs )
		throws SAXException
		{
		}

		public void endElement(
			String		uri,
			String		localName,
			String		qName )
		throws SAXException
		{
		}
	}

	// Loader behaviour configuration accessors

	public LoaderBehaviourEnum getClusterLoaderBehaviour() {
		return( clusterLoaderBehaviour );
	}

	public void setClusterLoaderBehaviour( LoaderBehaviourEnum value ) {
		clusterLoaderBehaviour = value;
	}

	public LoaderBehaviourEnum getISOCcyLoaderBehaviour() {
		return( iSOCcyLoaderBehaviour );
	}

	public void setISOCcyLoaderBehaviour( LoaderBehaviourEnum value ) {
		iSOCcyLoaderBehaviour = value;
	}

	public LoaderBehaviourEnum getISOCtryLoaderBehaviour() {
		return( iSOCtryLoaderBehaviour );
	}

	public void setISOCtryLoaderBehaviour( LoaderBehaviourEnum value ) {
		iSOCtryLoaderBehaviour = value;
	}

	public LoaderBehaviourEnum getISOCtryCcyLoaderBehaviour() {
		return( iSOCtryCcyLoaderBehaviour );
	}

	public void setISOCtryCcyLoaderBehaviour( LoaderBehaviourEnum value ) {
		iSOCtryCcyLoaderBehaviour = value;
	}

	public LoaderBehaviourEnum getISOCtryLangLoaderBehaviour() {
		return( iSOCtryLangLoaderBehaviour );
	}

	public void setISOCtryLangLoaderBehaviour( LoaderBehaviourEnum value ) {
		iSOCtryLangLoaderBehaviour = value;
	}

	public LoaderBehaviourEnum getISOLangLoaderBehaviour() {
		return( iSOLangLoaderBehaviour );
	}

	public void setISOLangLoaderBehaviour( LoaderBehaviourEnum value ) {
		iSOLangLoaderBehaviour = value;
	}

	public LoaderBehaviourEnum getISOTZoneLoaderBehaviour() {
		return( iSOTZoneLoaderBehaviour );
	}

	public void setISOTZoneLoaderBehaviour( LoaderBehaviourEnum value ) {
		iSOTZoneLoaderBehaviour = value;
	}

	public LoaderBehaviourEnum getSecClusGrpLoaderBehaviour() {
		return( secClusGrpLoaderBehaviour );
	}

	public void setSecClusGrpLoaderBehaviour( LoaderBehaviourEnum value ) {
		secClusGrpLoaderBehaviour = value;
	}

	public LoaderBehaviourEnum getSecClusGrpIncLoaderBehaviour() {
		return( secClusGrpIncLoaderBehaviour );
	}

	public void setSecClusGrpIncLoaderBehaviour( LoaderBehaviourEnum value ) {
		secClusGrpIncLoaderBehaviour = value;
	}

	public LoaderBehaviourEnum getSecClusGrpMembLoaderBehaviour() {
		return( secClusGrpMembLoaderBehaviour );
	}

	public void setSecClusGrpMembLoaderBehaviour( LoaderBehaviourEnum value ) {
		secClusGrpMembLoaderBehaviour = value;
	}

	public LoaderBehaviourEnum getSecSessionLoaderBehaviour() {
		return( secSessionLoaderBehaviour );
	}

	public void setSecSessionLoaderBehaviour( LoaderBehaviourEnum value ) {
		secSessionLoaderBehaviour = value;
	}

	public LoaderBehaviourEnum getSecSysGrpLoaderBehaviour() {
		return( secSysGrpLoaderBehaviour );
	}

	public void setSecSysGrpLoaderBehaviour( LoaderBehaviourEnum value ) {
		secSysGrpLoaderBehaviour = value;
	}

	public LoaderBehaviourEnum getSecSysGrpIncLoaderBehaviour() {
		return( secSysGrpIncLoaderBehaviour );
	}

	public void setSecSysGrpIncLoaderBehaviour( LoaderBehaviourEnum value ) {
		secSysGrpIncLoaderBehaviour = value;
	}

	public LoaderBehaviourEnum getSecSysGrpMembLoaderBehaviour() {
		return( secSysGrpMembLoaderBehaviour );
	}

	public void setSecSysGrpMembLoaderBehaviour( LoaderBehaviourEnum value ) {
		secSysGrpMembLoaderBehaviour = value;
	}

	public LoaderBehaviourEnum getSecTentGrpLoaderBehaviour() {
		return( secTentGrpLoaderBehaviour );
	}

	public void setSecTentGrpLoaderBehaviour( LoaderBehaviourEnum value ) {
		secTentGrpLoaderBehaviour = value;
	}

	public LoaderBehaviourEnum getSecTentGrpIncLoaderBehaviour() {
		return( secTentGrpIncLoaderBehaviour );
	}

	public void setSecTentGrpIncLoaderBehaviour( LoaderBehaviourEnum value ) {
		secTentGrpIncLoaderBehaviour = value;
	}

	public LoaderBehaviourEnum getSecTentGrpMembLoaderBehaviour() {
		return( secTentGrpMembLoaderBehaviour );
	}

	public void setSecTentGrpMembLoaderBehaviour( LoaderBehaviourEnum value ) {
		secTentGrpMembLoaderBehaviour = value;
	}

	public LoaderBehaviourEnum getSecUserLoaderBehaviour() {
		return( secUserLoaderBehaviour );
	}

	public void setSecUserLoaderBehaviour( LoaderBehaviourEnum value ) {
		secUserLoaderBehaviour = value;
	}

	public LoaderBehaviourEnum getSecUserPWHistoryLoaderBehaviour() {
		return( secUserPWHistoryLoaderBehaviour );
	}

	public void setSecUserPWHistoryLoaderBehaviour( LoaderBehaviourEnum value ) {
		secUserPWHistoryLoaderBehaviour = value;
	}

	public LoaderBehaviourEnum getSecUserPasswordLoaderBehaviour() {
		return( secUserPasswordLoaderBehaviour );
	}

	public void setSecUserPasswordLoaderBehaviour( LoaderBehaviourEnum value ) {
		secUserPasswordLoaderBehaviour = value;
	}

	public LoaderBehaviourEnum getSysClusterLoaderBehaviour() {
		return( sysClusterLoaderBehaviour );
	}

	public void setSysClusterLoaderBehaviour( LoaderBehaviourEnum value ) {
		sysClusterLoaderBehaviour = value;
	}

	public LoaderBehaviourEnum getTenantLoaderBehaviour() {
		return( tenantLoaderBehaviour );
	}

	public void setTenantLoaderBehaviour( LoaderBehaviourEnum value ) {
		tenantLoaderBehaviour = value;
	}

	// Parse a file

	public void parseFile( String url ) {
		parse( url );
	}
}
