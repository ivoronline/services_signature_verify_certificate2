package xmlutil;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyStore;

public class XMLUtil {

  //================================================================================
  // READ XML FROM FILE
  //================================================================================
  // Document document = readXMLFromFile(fileXMLInput);
  public static Document readXMLFromFile(String fileName) throws Exception {
    DocumentBuilderFactory documentFactory = DocumentBuilderFactory.newInstance();
    documentFactory.setNamespaceAware(true);
    Document document = documentFactory.newDocumentBuilder().parse(new FileInputStream(fileName));
    return document;
  }

  //================================================================================
  // GET PUBLIC KEY PAIR
  //================================================================================
  // KeyStore.TrustedCertificateEntry keyPair = XMLUtil.getPublicKeyPair(keyStoreName, keyStorePassword, keyStoreType, keyAlias);
  public static KeyStore.TrustedCertificateEntry getPublicKeyPair(
    String keyStoreName,        //"src/main/resources/ClientKeyStore.jks"
    String keyStorePassword,    //"mypassword"
    String keyStoreType,        //"JKS"
    String keyAlias             //"clientkeys1"
  ) throws Exception {

    //GET PRIVATE KEY
    char[]   password = keyStorePassword.toCharArray();                    //For KeyStore only
    KeyStore keyStore = KeyStore.getInstance(keyStoreType);
             keyStore.load(new FileInputStream(keyStoreName), password);
  //KeyStore.PasswordProtection keyPassword = new KeyStore.PasswordProtection(password);
    KeyStore.TrustedCertificateEntry keyPair = (KeyStore.TrustedCertificateEntry) keyStore.getEntry(keyAlias, null);

    //RETURN KEY PAIR
    return keyPair;

  }

  //================================================================================
  // VALIDATE SIGNATURE
  //================================================================================
  // boolean valid = XMLUtil.validateSignature(document, publicKey);
  public static boolean validateSignatureUsingKey(
    Document document,
    Key      key
  ) throws Exception  {

    //GET SIGNATURE NODE
    Node signatureNode = document.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature").item(0);

    //VALIDATE SIGNATURE
    DOMValidateContext valContext = new DOMValidateContext(key, signatureNode);
                        valContext.setIdAttributeNS((Element) signatureNode.getParentNode(),null,"Id"); //FIX
    XMLSignatureFactory factory    = XMLSignatureFactory.getInstance("DOM");
    XMLSignature        signature  = factory.unmarshalXMLSignature(valContext);
    boolean             valid      = signature.validate(valContext);

    //RETURN RESULT
    return valid;

  }

}
