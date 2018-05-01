package makeCxTeam;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.StringReader;
import java.io.StringWriter;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.soap.MessageFactory;
import javax.xml.soap.SOAPConnection;
import javax.xml.soap.SOAPConnectionFactory;
import javax.xml.soap.SOAPMessage;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import java.net.URL;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.crypto.Cipher;
import java.util.Base64;

public class makeCxTeam 
{
	public static String VERSION = "1.2";
	public static String SERVERURI = "http://localhost/CxWebInterface/Portal/CxWebService.asmx";
	public static String CxSessionID = null;
	public static boolean verbose = false;
	public static String un = "admin@cx";
	public static String pw = "admin";
	public static String pw_enc = "hello";
	public static String enk = Properties.get();
	public static String constCryptoAlgorithm = "Blowfish";
	public static boolean https = false;
	
	public static void main(String[] args) 
	{
		if(args.length == 5)
			subMain(args);
		else if(args.length == 1)
		{
			pw = args[0];
			encryptPassword();
		}//end else
		else
		{
			System.out.println("makeCxTeam:  Adds a team to Checkmarx");
			System.out.println("Written by Chris Merritt (chris.merritt@checkmarx.com)");
			System.out.println(VERSION + " - Last updated 08 September 2017 1510");
			System.out.println();
			System.out.println("makeCxTeam [full team path to add] [verbose: true|false] [cxusername] [cxpasswordEnc] [CxServer URL]");
			System.out.println("makeCxTeam SP\\Aviation\\Alpha\\0 false admin@cx passwordEnc http://localhost");
			System.out.println("makeCxTeam SP\\Financial\\Projectrs true admin@cx passwordEnc http://localhost");
		}//end else				
	}//end main
	
	public static void encryptPassword() 
	{
		try {
			String base64Encrypted = encrypt(pw, enk);
			System.out.println(base64Encrypted);
		} //end try
		catch (Exception e) 
		{
			System.out.println("Failed to encrypt password!");				
		}//end catch
	}//end encryptPassword

	public static void subMain(String[] args)
	{
		un = args[2];
		pw = args[3];
		if(args[4].toLowerCase().startsWith("https"))
			https = true;
		SERVERURI = args[4] + "/CxWebInterface/Portal/CxWebService.asmx";
				
		SOAPMessage sessionSM = getSessionID();
		
		CxSessionID = getValue(sessionSM, "<SessionId>", "</SessionId>");
		if(verbose)
			System.out.println("Session ID:  " + CxSessionID);
	
		String newTeam = args[0];
		if(args[1].toUpperCase().equals("TRUE"))
			verbose = true;
		
		checkAndAddNodes(newTeam);
		System.out.println(confirmNewTeam(newTeam));
	}//end subMain
	
	public static String confirmNewTeam(String team)
	{
		SOAPMessage teamTree = getHirearchyGroupTree();
		Document d = parseXml(teamTree);
		boolean flag = false;
		NodeList n = d.getElementsByTagName("FullPath");
		for(int i = 0; i < n.getLength(); i++)
		{
			if(n.item(i).getFirstChild().getNodeValue().toUpperCase().equals(team.toUpperCase()))
				flag = true; //path exists
		}//end if
		
		if(flag)
			return "SUCCESS";
		else
			return "FAILED";
	}//end confirmNewTeam

	public static void checkAndAddNodes(String path)
	{
		String[] pathNodes = path.split("\\\\");
		path = "";
		for(int i = 0; i < pathNodes.length; i++)
		{
			SOAPMessage teamTree = getHirearchyGroupTree();
			
			Document d = parseXml(teamTree);
			path = path + pathNodes[i] + "\\";
			if(verbose)
				System.out.print(path);

			String parentID = getParentIDifPathDoesNotExist(path, d);

			if(parentID == null && verbose)
				System.out.println("  ... Already exists");
			else if(parentID != null && parentID.equals("ERROR") && verbose)
				System.out.println("  ... Error, could not find parent ID; please check permissions.");
			else 
			{
				if(parentID != null)
				{
					createNewTeam(parentID, pathNodes[i]);
					if(verbose)
						System.out.println("  ... Adding path");
				}//end if
			}//end else
		}//end for
	}//end checkAndAddNodes
	
	public static String getParentIDifPathDoesNotExist(String path, Document d)
	{
		String parentID = null;
		boolean flag = false;
		NodeList n = d.getElementsByTagName("FullPath");
		
		for(int i = 0; i < n.getLength(); i++)
		{
			String fp = n.item(i).getFirstChild().getNodeValue().toUpperCase();
			if(fp.startsWith("\\"))
				fp = fp.substring(1);
			if(path.endsWith("\\"))
				path = path.substring(0, path.length()-1);
			
			if(fp.equals(path.toUpperCase()))
				flag = true; //path exists
		}//end if
		
		if(!flag)
		{
			try
			{
				path = path.substring(0,path.lastIndexOf("\\"));
				for(int i = 0; i < n.getLength(); i++)
				{
					String fp = n.item(i).getFirstChild().getNodeValue().toUpperCase();
					if(fp.startsWith("\\"))
						fp = fp.substring(1);
					
					if(fp.equals(path.toUpperCase()))
					{
						parentID = n.item(i).getPreviousSibling().getFirstChild().getNodeValue().toString();
					}//end if
				}//end if
			}//end try
			catch(Exception ex)
			{
				parentID = null;
			}//end catch
		}//end if

		//returns null if node already exists
		//if node does not exist, returns the id of the parent node
		if(!flag && parentID != null)
			return parentID;
		else if(flag && parentID == null)
			return null;
		else
			return "ERROR";
	}//end getParentIDifPathDoesNotExist
	
	public static SOAPMessage getHirearchyGroupTree()
	{
		try
		{
			String s = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n" + 
					"<soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\r\n" + 
					"  <soap:Body>\r\n" + 
					"    <GetHierarchyGroupTree xmlns=\"http://Checkmarx.com\">\r\n" + 
					"      <sessionID>" + CxSessionID + "</sessionID>\r\n" + 
					"    </GetHierarchyGroupTree>\r\n" + 
					"  </soap:Body>\r\n" + 
					"</soap:Envelope>";
			SOAPMessage message = send(buildSOAPMessage(s));
			return message;
		}//end try
		catch(Exception ex)
		{
			ex.printStackTrace();
			return null;
		}//end catch
	}//end getHirearchyGroupTree
	
	public static SOAPMessage createNewTeam(String parentID, String newTeamName)
	{
		try
		{
			String s = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n" + 
					"<soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\r\n" + 
					"  <soap:Body>\r\n" + 
					"    <CreateNewTeam xmlns=\"http://Checkmarx.com\">\r\n" + 
					"      <sessionID>" + CxSessionID + "</sessionID>\r\n" + 
					"      <parentTeamID>" + parentID + "</parentTeamID>\r\n" + 
					"      <newTeamName>" + newTeamName + "</newTeamName>\r\n" + 
					"    </CreateNewTeam>\r\n" + 
					"  </soap:Body>\r\n" + 
					"</soap:Envelope>";
			SOAPMessage message = send(buildSOAPMessage(s));
			return message;
		}//end try
		catch(Exception ex)
		{
			ex.printStackTrace();
			return null;
		}//end catch
	}//end createNewTeam
	
	public static SOAPMessage buildSOAPMessage(String message)
	{
		try
		{
		InputStream is = new ByteArrayInputStream(message.getBytes());
		SOAPMessage request = MessageFactory.newInstance().createMessage(null, is);
		return request;
		}//end try
		catch(Exception ex)
		{
			ex.printStackTrace();
			return null;
		}//end catch
	}//end buildSOAP Message
	
	public static String getValue(SOAPMessage message, String begintag, String endtag)
	{
		//This is the poor-man's way of retrieving a value from a SOAP response.
		
		try
		{
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			message.writeTo(out);
			String s = new String(out.toByteArray());
			s = s.substring(s.indexOf(begintag) + begintag.length(), s.indexOf(endtag));
			return s;
		}
		catch(Exception ex)
		{
			ex.printStackTrace();
			return null;
		}//end catch
	}//end getValue
	
	public static SOAPMessage getSessionID()
	{
		//Any SOAP request sent to Checkmarx must have a valid session ID.
		//This method crafts the request to get a session ID from Checkmarx
		//The session will assume the identity/permissions of the username and password provided
		try
		{
			String s = "<?xml version=\"1.0\" encoding=\"utf-8\"?>" +
					"<soap12:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap12=\"http://www.w3.org/2003/05/soap-envelope\">" +
					  "<soap12:Body>" +
					    "<LoginV2 xmlns=\"http://Checkmarx.com\">" +
					      "<applicationCredentials>" +
					        "<User>" + un + "</User>" +
					        "<Pass>" + decrypt(pw, enk) + "</Pass>" +
					      "</applicationCredentials>" +
					      "<lcid>0</lcid>" +
					      "<useExistingSession>false</useExistingSession>" +
					    "</LoginV2>" +
					  "</soap12:Body>" +
					"</soap12:Envelope>";
			SOAPMessage message = send(buildSOAPMessage(s));
			return message;
		}//end try
		catch(Exception ex)
		{
			ex.printStackTrace();
			return null;
		}//end catch
	}//end getSessionID

	public static SOAPMessage send(SOAPMessage sm)
	{
		if(https)
			return sendSecure(sm);
		else
		{
			try 
			{
	            SOAPConnectionFactory soapConnectionFactory = SOAPConnectionFactory.newInstance();
	            SOAPConnection soapConnection = soapConnectionFactory.createConnection();
	            SOAPMessage soapResponse = soapConnection.call(sm, SERVERURI);
	            soapConnection.close();
	            return soapResponse;
	        }//end try
			catch (Exception ex) 
			{
	            ex.printStackTrace();
	            return null;
	        }//end catch
		}
	}//end send
	
	public static SOAPMessage sendSecure(SOAPMessage request) 
	{
	    try 
	    {
	        final boolean isHttps = https;
	        HttpsURLConnection httpsConnection = null;
	        if (isHttps) 
	        {
	            SSLContext sslContext = SSLContext.getInstance("SSL");
	            TrustManager[] trustAll = new TrustManager[] {new TrustAllCertificates()};
	            sslContext.init(null, trustAll, new java.security.SecureRandom());
	            HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
	            URL url = new URL(SERVERURI);
	            httpsConnection = (HttpsURLConnection) url.openConnection();
	            httpsConnection.setHostnameVerifier(new TrustAllHosts());
	            httpsConnection.connect();
	        }//end if
	        SOAPConnection soapConnection = SOAPConnectionFactory.newInstance().createConnection();
	        SOAPMessage response = soapConnection.call(request, SERVERURI);
	        soapConnection.close();
	        if (isHttps) 
	            httpsConnection.disconnect();
	        return response;
	    }//end try
	    catch (Exception ex) 
	    {
	        System.out.println(ex.getMessage());
	    }//end catch
	    
	    return null;
	}//end sendSecure

	public static Document parseXml(SOAPMessage message)
    {
		//This method converts the SOAP response to an XML document so that it may be parsed
        try
        {
        	ByteArrayOutputStream out = new ByteArrayOutputStream();
			message.writeTo(out);
			String s = new String(out.toByteArray());
			
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            InputSource is = new InputSource(new StringReader(s));
            return db.parse(is);
        } //end try
        catch (Exception e)
        {
            throw new RuntimeException(e);
        }//end catch
    }//end parseXml
	
	public static String getWholeMessage(SOAPMessage message)
	{
		//This method returns a string representation of the entire SOAP response from Checkmarx
		try
		{
			Transformer transformer = TransformerFactory.newInstance().newTransformer();
			transformer.setOutputProperty(OutputKeys.INDENT, "yes");
			transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
			//initialize StreamResult with File object to save to file
			StreamResult result = new StreamResult(new StringWriter());
			DOMSource source = new DOMSource(parseXml(message));
			transformer.transform(source, result);
			String xmlString = result.getWriter().toString();
			return xmlString;
		}
		catch(Exception ex)
		{
			ex.printStackTrace();
			return null;
		}//end catch
	}//end getWholeMessage

	public static String encrypt(String strClearText, String strKey) throws Exception
	{
		String base64Data = "";
		try {
			SecretKeySpec skeyspec=new SecretKeySpec(strKey.getBytes(),constCryptoAlgorithm);
			Cipher cipher=Cipher.getInstance(constCryptoAlgorithm);
			cipher.init(Cipher.ENCRYPT_MODE, skeyspec);
			byte[] encrypted=cipher.doFinal(strClearText.getBytes());
			base64Data = new String(Base64.getEncoder().encode(encrypted));
		}//end try
		catch (Exception e) 
		{
			e.printStackTrace();
			throw new Exception(e);
		}//end catch
		return base64Data;
	}//end encrypt

	public static String decrypt(String strBase64Encrypted, String strKey) throws Exception
	{
		String strData="";
		try 
		{
			byte[] bytesEncrypted = Base64.getDecoder().decode(strBase64Encrypted.getBytes());

			SecretKeySpec skeyspec=new SecretKeySpec(strKey.getBytes(),constCryptoAlgorithm);
			Cipher cipher=Cipher.getInstance(constCryptoAlgorithm);
			cipher.init(Cipher.DECRYPT_MODE, skeyspec);
			byte[] decrypted=cipher.doFinal(bytesEncrypted);
			strData=new String(decrypted);
		}//end try
		catch (Exception e) 
		{
			e.printStackTrace();
			throw new Exception(e);
		}//end catch
		
		return strData;
	}//end decrypt
}//end class makeCxTeam

class TrustAllHosts implements HostnameVerifier 
{
    public boolean verify(String hostname, SSLSession session) 
    {
        return true;
    }//end verify
}//end TrustAllHosts

class TrustAllCertificates implements X509TrustManager 
{
    public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) 
    {
    }//end checkClientTrusted
 
    public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) 
    {
    }//end checkServerTrusted
 
    public java.security.cert.X509Certificate[] getAcceptedIssuers() 
    {
        return null;
    }//end getAcceptedIssuers
}//end TrustAllCertificates
