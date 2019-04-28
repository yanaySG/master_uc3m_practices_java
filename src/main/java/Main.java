import com.sun.org.apache.xml.internal.security.utils.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.FileReader;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class Main {
/*
    static String AES = "AES";
    static String AESCBCPKCS7 = "AES/CBC/PKCS7Padding";
    static String SHA2 = "SHA-256";
    static SecretKeySpec key;
    static int KEYLENGTH = 16;

    private static final SecureRandom random = new SecureRandom();

    private static void printMaxKey(){
        int maxKeySize = 0;
        try {
            maxKeySize = javax.crypto.Cipher.getMaxAllowedKeyLength("AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        System.out.printf("**** AES:%d bits *****\n",maxKeySize);
    }

    private static X509Certificate loadCertificates(){
        try {

            CertificateFactory certFactory = CertificateFactory.getInstance("X.509", "BC");
            ClassLoader classloader = Thread.currentThread().getContextClassLoader();
            return  (X509Certificate) certFactory.generateCertificate(classloader.getResourceAsStream("baeldung.cer"));
        }
        catch(Exception e ){
            e.printStackTrace();
            return null;
        }
    }


    private static PrivateKey loadPrivateKey(){
        try {
            char[] keystorePassword = "password".toCharArray();
            char[] keyPassword = "password".toCharArray();

            KeyStore keystore = KeyStore.getInstance("PKCS12");
            ClassLoader classloader = Thread.currentThread().getContextClassLoader();
            keystore.load(classloader.getResourceAsStream("baeldung.p12"), keystorePassword);
            return (PrivateKey) keystore.getKey("baeldung", keyPassword);
        }
        catch(Exception e ){
            e.printStackTrace();
            return null;
        }
    }

    public static String readFile(String filename){

        StringBuilder sb = new StringBuilder();

        try{
                BufferedReader br = new BufferedReader(new FileReader(filename));

                // read line by line
                String line;
                while ((line = br.readLine()) != null) {
                    sb.append(line).append("\n");
                }


        } catch (Exception e) {
            System.err.format("IOException: %s%n", e);
        }

        return sb.toString();
    }

    private static SecretKeySpec generateKey() {
        byte[] keyBytes = new byte[KEYLENGTH];
        random.nextBytes(keyBytes);
        return new SecretKeySpec(keyBytes, "AES");
    }

    public static byte[] toByte(String input){
        return input.getBytes();
    }

    public static byte[] getSHA2Byte(String text) throws Exception{
        if(text==null || text.length()<=0)
            return null;
        MessageDigest digest = MessageDigest.getInstance(SHA2);
        return digest.digest(text.getBytes(StandardCharsets.UTF_8));
    }

    public static String getSHA2Hex(String text) throws Exception{
        if(text==null || text.length()<=0)
            return null;
        return new String(Hex.encode(getSHA2Byte(text)));
    }

    public static SecretKeySpec generateKeyWithPassword(String password) throws Exception{
//        final MessageDigest digest = MessageDigest.getInstance(SHA2);
//        byte[] bytes = password.getBytes(StandardCharsets.UTF_8);
//        digest.update(bytes,0,bytes.length);
//        byte[] key = digest.digest();

        if(password==null || password.length()<=0)
            return null;
        return new SecretKeySpec(getSHA2Byte(password),AES);
    }

    public static String encrypt(String encString) throws Exception{

        Cipher cipher = Cipher.getInstance(AES);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encVal = cipher.doFinal(encString.getBytes());
        System.out.println(encVal.toString());
        System.out.println("*****************************");
        final String encryptedVal = Base64.encode(encVal, Base64.BASE64DEFAULTLENGTH);
        return encryptedVal;
    }

    public static String encrypt2(String encString) throws Exception {

        Cipher cipher = Cipher.getInstance(AES);
        byte[] iv = "0123456789abcdef".getBytes(StandardCharsets.US_ASCII);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encVal = cipher.doFinal(encString.getBytes());
        System.out.println(encVal.toString());
        System.out.println("*****************************");
        final String decString = new String(encVal);
        return decString;
    }

    public static String decrypt(String decString) throws Exception{
        Cipher cipher = Cipher.getInstance(AES);
        cipher.init(Cipher.DECRYPT_MODE, key);

        byte[] dec = Base64.decode(decString);
        byte[] decVal = cipher.doFinal(dec);
        final String decryptedVal = new String(decVal);
        return decryptedVal;
    }

    public static String decrypt2(String decString) throws Exception{
        Cipher cipher = Cipher.getInstance(AES);
        byte[] iv = "0123456789abcdef".getBytes(StandardCharsets.US_ASCII);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decval = cipher.doFinal(decString.getBytes());
        return new String(decval);
    }
*/
    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());

        System.out.println("******************************");
        System.out.println("******** MULTI-CYPHER ********");
      //  printMaxKey();
      //  loadCertificates();
     //   loadPrivateKey();

  //      String textfile = readFile("transaction.xml");
/*
        try {
            String pass = "lawtonbros";
            //key = generateKeyWithPassword(pass);
            key = generateKeyWithPassword(pass);
            String encstring = encrypt2(textfile);
            System.out.println(encstring);
             encstring = encrypt(textfile);
            System.out.println(encstring);
            System.out.println("**********************************");
            String decstring = decrypt2(encstring);
            System.out.println(decstring);
        }
        catch (Exception e){e.printStackTrace();}
*/


        int swValue;
        System.out.println("******************************");

        System.out.println("Menu:\n");
        System.out.println("1. Option 1 ");
        System.out.println("2. Option 2 ");
        System.out.println("3. Exit\n");

        swValue = Keyin.inInt("Select option: ");

        // Switch construct
        switch (swValue) {
            case 1:
                System.out.println("Option 1 selected");
                break;
            case 2:
                System.out.println("Option 2 selected");
                break;
            case 3:
                System.out.println("Exit selected");
                break;
            default:
                System.out.println("Invalid selection");
                break; // This break is not really necessary
        }
    }
}

class Keyin {

    //*******************************
    //   support methods
    //*******************************
    //Method to display the user's prompt string
    public static void printPrompt(String prompt) {
        System.out.print(prompt + " ");
        System.out.flush();
    }

    //Method to make sure no data is available in the
    //input stream
    public static void inputFlush() {
        int dummy;
        int bAvail;

        try {
            while ((System.in.available()) != 0)
                dummy = System.in.read();
        } catch (java.io.IOException e) {
            System.out.println("Input error");
        }
    }

    public static String inString() {
        int aChar;
        String s = "";
        boolean finished = false;

        while (!finished) {
            try {
                aChar = System.in.read();
                if (aChar < 0 || (char) aChar == '\n')
                    finished = true;
                else if ((char) aChar != '\r')
                    s = s + (char) aChar; // Enter into string
            } catch (java.io.IOException e) {
                System.out.println("Input error");
                finished = true;
            }
        }
        return s;
    }

    public static int inInt(String prompt) {
        while (true) {
            inputFlush();
            printPrompt(prompt);
            try {
                return Integer.valueOf(inString().trim()).intValue();
            } catch (NumberFormatException e) {
                System.out.println("Invalid input. Not an integer");
            }
        }
    }

}