import java.io.*;
import java.net.*;
import java.util.*;
import java.security.*;
import java.math.*;
import javax.crypto.*;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
public class Sb {
	public static String delimiter = "THIS_IS_A_DELIMITER";
	private KeyPairGenerator keyGen;
	 private KeyPair pair;
	 private PrivateKey privateKey;
	 private PublicKey publicKey;
	 
	public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
		int portnumberB;
		Scanner sc = new Scanner(System.in);
		System.out.println("Connect to Client on Port Number : ");
		portnumberB = sc.nextInt();
		System.out.println("Port number of Server B : " +portnumberB);
		ServerSocket ss = new ServerSocket(portnumberB);
		Socket S = ss.accept();
		
		OutputStream osb = S.getOutputStream();
        DataOutputStream bout = new DataOutputStream(osb);
        InputStream isb = S.getInputStream();
        DataInputStream din = new DataInputStream(isb);
        
        String msg = readMessage(din);
        System.out.println("Client says : " + msg);
        String ack = "Hii Client";
        bout.writeBytes(ack + delimiter);
        bout.flush();
        
        double R = Math.random();
        R = R * 10;
        int Rb = (int) R;
        int g = 7;
        int Wb = (int) Math.pow(g, Rb);
        String SWb = Integer.toString(Wb);
        String SWc = readMessage(din);
        System.out.println("Client's Wc : " + SWc);
        bout.writeBytes(SWb + delimiter);
        bout.flush();
        String ackSWb = readMessage(din);
        System.out.println(ackSWb);
        
        //Calculating Hash Value of SWc , SWb
        String HashSWb = GetHash(SWb);
        String HashSWc = GetHash(SWc);
        String SbHash = HashSWb + HashSWc ;
        bout.writeBytes(SbHash + delimiter);
        bout.flush();
        String ackBHash = readMessage(din);
        System.out.println(ackBHash);
        
        
      //Generating Key Pair
        PublicKey publickeyB;
        PrivateKey privatekeyB;
        Sb myKeys = new Sb(1024);
        myKeys.createKeys();
        publickeyB = myKeys.getPublicKey();
        privatekeyB = myKeys.getPrivateKey();
        
       // Encoding Public key 
        byte[] pubB = publickeyB.getEncoded();
        BASE64Encoder encoder = new BASE64Encoder();
        String pubkeyB = encoder.encode(pubB);
        
        //Passing Publickey to Client
        bout.writeBytes(pubkeyB + delimiter);
        bout.flush();
        String keyackB = readMessage(din);
        System.out.println(keyackB);
        
        //GettingEncryptedKey
        String sendEncrypted = " Send me Encrypted second split";
        bout.writeBytes(sendEncrypted + delimiter); 
        bout.flush();
        String EncryptB = readMessage(din);
        System.out.println("Encrypted password of Server B : " + EncryptB);
       // byte[] EncB = EncryptB.getBytes();
        BASE64Decoder dec = new BASE64Decoder();
        byte [] EncB = dec.decodeBuffer(EncryptB);
        //Decrypting information
        
        String DecryptB = decrypt(privatekeyB , EncB);
        System.out.println("Decrypted Split for Server B : " + DecryptB);
        
       //Calculating Session keys 
        int Wc = Integer.parseInt(SWc);
        int skBC = (int) Math.pow(Wc, Rb);
        System.out.println("Session keys for Server B - Client Communication : " + skBC);
        
        File file = new File("E:/Project/File/ServerB.txt");
        FileOutputStream fop = new FileOutputStream(file) ;
        fop.write(DecryptB.getBytes());
        fop.flush();
        fop.close();
        
        S.close();
}
	public static String decrypt(PrivateKey key, byte[] text) {
	    byte[] decryptedText = null;
	    String decText = null ;
	    try {
	      // get an RSA cipher object and print the provider
	      final Cipher cipher = Cipher.getInstance("RSA");

	      // decrypt the text using the private key
	      cipher.init(Cipher.DECRYPT_MODE, key);
	      decryptedText = cipher.doFinal(text);
	      decText = new String(decryptedText);
	    } catch (Exception ex) {
	      ex.printStackTrace();
	    }

	    return decText ;
	  }
	
	public static String GetHash(String message) throws NoSuchAlgorithmException , IOException{
    	MessageDigest digest = MessageDigest.getInstance("SHA1");
    	byte[] hashedBytes = digest.digest(message.getBytes("UTF-8"));
    	return convertToHex(hashedBytes);
    }
    private static String convertToHex(byte[] arrayBytes){
    	StringBuffer stringBuffer = new StringBuffer();
    	for(int i=0; i < arrayBytes.length; i++){
    		stringBuffer.append(Integer.toString((arrayBytes[i] & 0xff)+ 0x100,16).substring(1));
    	}
    	return stringBuffer.toString();

}
    
    public Sb(int keylength) throws NoSuchAlgorithmException, NoSuchProviderException {

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
    
    
	
	public static String readMessage(DataInputStream din) {
    	byte[] messageByte = new byte[10000];
    	boolean end = false;
    	int bytesRead=0;
    	String messageString = "";
    	while(!end)
        {
    		try {
				bytesRead = din.read(messageByte);
			} catch (IOException e) {
				e.printStackTrace();
			}
    		if(bytesRead == -1)
            	break;
            messageString += new String(messageByte, 0, bytesRead);
            if((messageString.length()  >= delimiter.length()) && messageString.substring(messageString.length()-delimiter.length()).equals(delimiter)) {
            	break;
            }
        }
    	return messageString.substring(0, messageString.length()-delimiter.length());
    }
}
