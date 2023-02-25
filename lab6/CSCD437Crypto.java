/*
 * I have provided a Java main, and Javadoc of a Java class. Your task is to write the Java class. This Java class is 
 * meant to simulate the basics similar to PGP. ]
 * 1) Write the CSCD437Crypto.java code based on the Javadoc specifications. NOTE: the code is within a package. 
 * 2) Using the message.txt file execute CSCD437Lab6Tester.java and capture the output. 
 * 3) Capture the output and place the output in the single PDF
 */

package lab6;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class CSCD437Crypto {
    private String asymmetricAlgorithm;
    private String symmetricAlgorithm;
    private int keySize;

    private PublicKey publicKey;
    private PrivateKey privateKey;

    public CSCD437Crypto(String asymmetricAlgorithm, String symmetricAlgorithm, int keySize)
            throws NoSuchAlgorithmException {
        this.asymmetricAlgorithm = asymmetricAlgorithm;
        this.symmetricAlgorithm = symmetricAlgorithm;
        this.keySize = keySize;
        generateKeys(symmetricAlgorithm, symmetricAlgorithm, keySize);
    }

    // generates a new public and private key pair supports RSA and DSA
    public void generateKeys(String asymmetricAlgorithm, String symmetricAlgorithm, int keySize)
            throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(symmetricAlgorithm);
        keyPairGenerator.initialize(keySize);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        publicKey = keyPair.getPublic();
        privateKey = keyPair.getPrivate();
    }

    // publishes the public key to a file
    public void publishPublicKey(String fileName) throws IOException {
        try (FileOutputStream outputStream = new FileOutputStream(fileName)) {
            byte[] publicKeyBytes = publicKey.getEncoded();
            outputStream.write(publicKeyBytes);
        }
    }

    // reads in a public key from a file
    public static PublicKey getPublicKey(String fileName)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyBytes = Files.readAllBytes(Paths.get(fileName));
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    // encrypts a message with a specified public key and writes it to a file
    public void encrypt(PublicKey key, String padding, String message, String fileName)
            throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(padding);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedMessage = cipher.doFinal(message.getBytes());
        try (FileOutputStream outputStream = new FileOutputStream(fileName)) {
            outputStream.write(encryptedMessage);
        }
    }

    // encrypts a file with a specified public key and writes it to a file
    public void encrypt(PublicKey key, String padding, File fileToEncrypt, String fileName)
            throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(padding);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] fileBytes = Files.readAllBytes(fileToEncrypt.toPath());
        byte[] encryptedMessage = cipher.doFinal(fileBytes);
        try (FileOutputStream outputStream = new FileOutputStream(fileName)) {
            outputStream.write(encryptedMessage);
        }
    }

    // decrypts a file with a specified private key and writes it to a file
    public void decrypt(String fileName, String padding) throws IOException, NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(padding);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] encryptedMessage = Files.readAllBytes(Paths.get(fileName));
        byte[] decryptedMessage = cipher.doFinal(encryptedMessage);
        System.out.println(new String(decryptedMessage));
    }
}
