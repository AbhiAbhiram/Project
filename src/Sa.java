import java.io.*;
import java.net.*;
import java.util.*;
import java.security.*;
import java.math.*;
import javax.crypto.*;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class Sa {
	public static String delimiter = "THIS_IS_A_DELIMITER";
	private KeyPairGenerator keyGen;
	 private KeyPair pair;
	 private PrivateKey privateKey;
	 private PublicKey publicKey;
	 
	public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
		int portnumberA;
		Scanner sc = new Scanner(System.in);
		System.out.print("Connect to Client on Port Number : ");
		portnumberA = sc.nextInt();
		System.out.println("Port Number of Server A : " +  portnumberA);
		ServerSocket ss = new ServerSocket(portnumberA);
		Socket S = ss.accept();
		
		OutputStream osa = S.getOutputStream();  // Server A  's Input & Output Streams //
		DataOutputStream aout = new DataOutputStream(osa);
		InputStream isa = S.getInputStream();
        DataInputStream din = new DataInputStream(isa);
        
        String msgfrmClient = readMessage(din); //1R
        System.out.println("Client says : " + msgfrmClient);
        String ack = "Hello Client";
        aout.writeBytes(ack + delimiter); //2W
        aout.flush();
        
        double R = Math.random();
        R = R * 10;
        int Ra = (int) R;
        int g = 7;
        int Wa = (int) Math.pow(g, Ra);
        String SWa = Integer.toString(Wa);
        String SWc = readMessage(din); //3R
        System.out.println("Client's Wc : " + SWc);
        int Wc = Integer.parseInt(SWc);
        aout.writeBytes(SWa + delimiter); //4W
        aout.flush();
        String ackSWa = readMessage(din); //5R
        System.out.println(ackSWa);
        
        //Calculating Hash Value of SWa , SWc
        String HashSWa = GetHash(SWa);
        String HashSWc = GetHash(SWc);
        String SaHash = HashSWa + HashSWc ;
        System.out.println("Hash Generated on Server A : " + SaHash);
        aout.writeBytes(SaHash + delimiter); //6W
        aout.flush();
        String ackAHash = readMessage(din); //7R
        System.out.println(ackAHash);
        
        //Generating Key Pair
        PublicKey publickeyA;
        PrivateKey privatekeyA;
        Sa myKeys = new Sa(1024);
        myKeys.createKeys();
        publickeyA = myKeys.getPublicKey();
        privatekeyA = myKeys.getPrivateKey();
        System.out.println("Public key of Server A : " + publickeyA);
        System.out.println("Private key of Server A: " + privatekeyA);
        
        //Encoding Publickey into a String
        
        byte[] pubA = publickeyA.getEncoded();
        BASE64Encoder encoder = new BASE64Encoder();
        String pubkeyA = encoder.encode(pubA);
        System.out.println("Public key after encoding on Server : " + pubkeyA);
        //Passing Publickey to Client
        aout.writeBytes(pubkeyA + delimiter); //8W
        aout.flush();
        String keyackA = readMessage(din); //9R
        
       //Getting Encrypted key
        String sendEncrypted = " Send me Encrypted first split";
        aout.writeBytes(sendEncrypted + delimiter); //10W
        aout.flush();
        String EncryptA = readMessage(din); //11R
        System.out.println("Encrypted Password of Server a: " + EncryptA);
        
        BASE64Decoder dec = new BASE64Decoder();
        byte [] EncA = dec.decodeBuffer(EncryptA);
       
        //Decrypting information
        
        String DecryptA = decrypt(privatekeyA , EncA);
        System.out.println("Decrypted Split for Server A : " + DecryptA);
        
        //Calculating Session keys
        int skAC = (int) Math.pow(Wc, Ra);
        System.out.println("Session Key for Server A - Client : " + skAC);
        
        File file = new File("E:/Project/File/ServerA.txt");
        FileOutputStream fop = new FileOutputStream(file) ;
        fop.write(DecryptA.getBytes());
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
    
    public Sa(int keylength) throws NoSuchAlgorithmException, NoSuchProviderException {

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
