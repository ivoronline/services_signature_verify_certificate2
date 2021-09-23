import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PublicKey;

public class UtilSignature {

  //================================================================================
  // GET PUBLIC KEY FROM KEY STORE
  //================================================================================
  // KeyStore.TrustedCertificateEntry keyPair = XMLUtil.getPublicKeyPair(keyStoreName, keyStorePassword, keyStoreType, keyAlias);
  public static PublicKey getPublicKeyFromKeyStore(
    String keyStoreName,        //"/ClientKeyStore.jks"
    String keyStorePassword,    //"mypassword"
    String keyStoreType,        //"JKS"
    String keyAlias             //"clientkeys1"
  ) throws Exception {

    //GET PUBLIC KEY
    InputStream inputStream = UtilSignature.class.getResourceAsStream(keyStoreName);
    char[]      password    = keyStorePassword.toCharArray();                    //For KeyStore only
    KeyStore    keyStore    = KeyStore.getInstance(keyStoreType);
                keyStore.load(inputStream, password);
  //KeyStore.PasswordProtection keyPassword = new KeyStore.PasswordProtection(password);
    KeyStore.TrustedCertificateEntry keyPair = (KeyStore.TrustedCertificateEntry) keyStore.getEntry(keyAlias, null);

    PublicKey publicKey = keyPair.getTrustedCertificate().getPublicKey();

    //RETURN KEY PAIR
    return publicKey;

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
