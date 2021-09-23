import java.io.InputStream;
import java.security.KeyStore;
import java.security.PublicKey;

public class UtilKeys {

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

    //GET KEY STORE
    InputStream inputStream = UtilKeys.class.getResourceAsStream(keyStoreName);
    char[]      password    = keyStorePassword.toCharArray();                    //For KeyStore only
    KeyStore    keyStore    = KeyStore.getInstance(keyStoreType);
                keyStore.load(inputStream, password);

    //GET PUBLIC KEY
    KeyStore.TrustedCertificateEntry keyPair = (KeyStore.TrustedCertificateEntry) keyStore.getEntry(keyAlias, null);
    PublicKey publicKey = keyPair.getTrustedCertificate().getPublicKey();

    //RETURN PUBLIC KEY
    return publicKey;

  }

}
