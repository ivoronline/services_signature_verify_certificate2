import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import java.security.Key;

public class UtilSignature {

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
