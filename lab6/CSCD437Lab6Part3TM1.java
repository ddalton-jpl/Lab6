package lab6;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class CSCD437Lab6Part3TM1 {
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
              // Alice create public and private keys using the default of SHA256withRSA
      CSCD437Crypto tm1Crypto = new CSCD437Crypto("SHA256withRSA", "RSA", 1024);
      
      // Alice publishes the public key 
      tm1Crypto.publishPublicKey("teamMember1.asc");
            
      // Bob creates public and private keys using a Java defined algorithm
      CSCD437Crypto tm2Crypto = new CSCD437Crypto("SHA256withRSA", "RSA", 1024);
      
      // Bob downloads Alice's public key 
      PublicKey tm1Key = CSCD437Crypto.getPublicKey("teamMember1.asc");
            
      // Bob encrypts a message to Alice
      tm2Crypto.encrypt(tm1Key, "RSA/ECB/PKCS1Padding", "this is a test", "message.enc");
            
      // Alice decrypts Bob's message using Alice's private key
      tm1Crypto.decrypt("message.enc", "RSA/ECB/PKCS1Padding");
      
      System.out.println("\n");
    }
}
