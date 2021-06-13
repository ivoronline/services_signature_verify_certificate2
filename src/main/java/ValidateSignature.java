import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PublicKey;

public class ValidateSignature {

  //KEY STORE
  static String keyStoreName     = "src/main/resources/PublicKeys.jks";
  static String keyStorePassword = "mypassword";
  static String keyStoreType     = "JKS";
  static String keyAlias         = "clientkeys1";

  //XML FILE
  static String fileXMLInput1    = "src/main/resources/PersonSigned.xml";
  static String fileXMLInput2    = "src/main/resources/PersonSignedWithKeyInfo.xml";

  //================================================================================
  // MAIN
  //================================================================================
  public static void main(String[] args) throws Exception {

    //VALIDATE SIGNATURE
    Document  document  = readXMLFromFile(fileXMLInput1);
    KeyStore.TrustedCertificateEntry keyPair = getTrustedKeyPair(keyStoreName, keyStorePassword, keyStoreType, keyAlias);
    PublicKey publicKey = keyPair.getTrustedCertificate().getPublicKey();
    boolean   valid     = validateSignature(document, "Person", publicKey);

    //DISPLAY RESULT
    System.out.println(valid);

  }

  //================================================================================
  // READ XML FROM FILE
  //================================================================================
  // Document document = readXMLFromFile(fileXMLInput);
  private static Document readXMLFromFile(String fileName) throws Exception {
    DocumentBuilderFactory documentFactory = DocumentBuilderFactory.newInstance();
    documentFactory.setNamespaceAware(true);
    Document document = documentFactory.newDocumentBuilder().parse(new FileInputStream(fileName));
    return document;
  }

  //================================================================================
  // GET TRUSTED KEY PAIR
  //================================================================================
  // KeyStore.PrivateKeyEntry keyPair = getKeyPair(keyStoreName, keyStorePassword, keyStoreType, keyAlias);
  private static KeyStore.TrustedCertificateEntry getTrustedKeyPair(
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
  private static boolean validateSignature(
    Document  document,
    String    elementName,
    PublicKey publicKey
  ) throws Exception  {

    //GET SIGNATURE NODE
    Node signatureNode = document.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature").item(0);

    //VALIDATE SIGNATURE
    DOMValidateContext  valContext = new DOMValidateContext(publicKey, signatureNode);
                        valContext.setIdAttributeNS((Element) signatureNode.getParentNode(),null,"Id"); //FIX
    XMLSignatureFactory factory    = XMLSignatureFactory.getInstance("DOM");
    XMLSignature        signature  = factory.unmarshalXMLSignature(valContext);
    boolean             valid      = signature.validate(valContext);

    //RETURN RESULT
    return valid;

  }

}
