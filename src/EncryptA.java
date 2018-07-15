import java.io.*;
import java.net.*;
import java.util.*;
import java.security.*;
import java.math.*;
import javax.crypto.*;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
public class EncryptA {
	private KeyPairGenerator keyGen;
	 private KeyPair pair;
	 private PrivateKey privateKey;
	 private PublicKey publicKey;
	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
		   //Generating Key Pair
        PublicKey publickeyA;
        PrivateKey privatekeyA;
        EncryptA myKeys = new EncryptA(1024);
        myKeys.createKeys();
        publickeyA = myKeys.getPublicKey();
        privatekeyA = myKeys.getPrivateKey();
        System.out.println("Public key : " + publickeyA);
        System.out.println("Private key : " + privatekeyA);
        
        String password = "1234";
        
      //Encryption
        byte[] Ea = encrypt(publickeyA , password);
        String EncryptA = new String(Ea);
        System.out.println("Encrypted password is : " + EncryptA);
        String DecryptA = decrypt(privatekeyA , EncryptA.getBytes());
        System.out.println("Decrypted password is : " + DecryptA); 
	}
	 public static byte[] encrypt(PublicKey key,String text) {
		    byte[] cipherText = null;
		    try {
		      // get an RSA cipher object and print the provider
		      final Cipher cipher = Cipher.getInstance("RSA");
		      // encrypt the plain text using the public key
		      cipher.init(Cipher.ENCRYPT_MODE, key);
		      cipherText = cipher.doFinal(text.getBytes());
		    } catch (Exception e) {
		      e.printStackTrace();
		    }
		    return cipherText;
		  }

    
	public static String decrypt(PrivateKey key,byte[] text) {
	    byte[] dectyptedText = null;
	    try {
	      // get an RSA cipher object and print the provider
	      final Cipher cipher = Cipher.getInstance("RSA");
	      
	      // decrypt the text using the private key
	      cipher.init(Cipher.DECRYPT_MODE, key);
	      dectyptedText = cipher.doFinal(text);
	      
	    } catch (Exception ex) {
	      ex.printStackTrace();
	    }
	    
	    return new String(dectyptedText);
	  }
	
	public EncryptA(int keylength) throws NoSuchAlgorithmException, NoSuchProviderException {

        this.keyGen = KeyPairGenerator.getInstance("RSA");
        this.keyGen.initialize(keylength);
    }

    public void createKeys() {
        this.pair = this.keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();

    }

    public PrivateKey getPrivateKey() {
        return this.privateKey;
    }

    public PublicKey getPublicKey() {
        return this.publicKey;
    }
    
}
