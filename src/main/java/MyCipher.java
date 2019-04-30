import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OutputEncryptor;
import sun.security.provider.SecureRandom;

import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;

public class MyCipher {

    static int INPUT_LENGTH = 1024;
    static int KEY_LENGTH = 16;
    static String DEFAULT_KEY = "ASDFGHJKLASDFGHJ";

    public static PrivateKey privateKey;
    public static X509Certificate certificate;


    public static void Init()  {
        Security.addProvider(new BouncyCastleProvider());

        try {
            loadCertificate();
            loadKeyStore();
        } catch (Exception e) {
            e.printStackTrace();
        }


    }

    public static void loadCertificate() throws NoSuchProviderException,CertificateException,IOException{
        CertificateFactory certFactory= CertificateFactory.getInstance("X.509", "BC");
        certificate = (X509Certificate) certFactory.generateCertificate(new FileInputStream("Baeldung.cer"));
    }

    public static void loadKeyStore() throws KeyStoreException, IOException, NoSuchAlgorithmException,UnrecoverableKeyException, CertificateException{
        char[] keystorePassword = "password".toCharArray();
        char[] keyPassword = "password".toCharArray();

        KeyStore keystore = KeyStore.getInstance("PKCS12");
        keystore.load(new FileInputStream("Baeldung.p12"), keystorePassword);
        privateKey = (PrivateKey) keystore.getKey("baeldung", keyPassword);
    }



    protected static byte[] encrypt(byte[] plainText, String key) throws InvalidCipherTextException {

        INPUT_LENGTH  = plainText.length;
        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()));
        cipher.init(true,new KeyParameter(key.getBytes()));
        byte[] rv = new byte[cipher.getOutputSize(plainText.length)];
        int tam = cipher.processBytes(plainText, 0, plainText.length, rv, 0);
        cipher.doFinal(rv, tam);
        return rv;
    }

    protected static byte[] decrypt(byte[] cipherText, String key) throws InvalidCipherTextException{

        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()));
        cipher.init(false, new KeyParameter(key.getBytes()));
        byte[] rv = new byte[cipher.getOutputSize(cipherText.length)];
        int tam = cipher.processBytes(cipherText, 0, cipherText.length, rv, 0);
        cipher.doFinal(rv, tam);
        rv = Arrays.copyOfRange(rv, 0, INPUT_LENGTH);
        return rv;
    }

    public static int DecryptFile(File file, String key, String outputfile) throws IOException, InvalidCipherTextException{
        if(file==null || !file.exists())
            return -1;

        byte[] encrypteddata = readFile(file);
        byte[] decrypteddata  = decrypt(encrypteddata,key);
        final String decryptedVal = new String(decrypteddata);
        System.out.println(decryptedVal);
        return writeFile(decrypteddata,outputfile);
    }

    public static int EncryptFile(File file, String key, String outputfile) throws IOException, InvalidCipherTextException{
        if(file==null || !file.exists())
            return -1;

        byte[] encrypteddata = encrypt(readFile(file),getKey(key));
        return writeFile(encrypteddata,outputfile);
    }

    public static String GetFileChecksum(File file) throws IOException, NoSuchAlgorithmException {
        FileInputStream inputStream = new FileInputStream(file);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        byte[] byteArray = new byte[(int)file.length()];
        int bytesCount;

        while ((bytesCount = inputStream.read(byteArray))!= -1){
            digest.update(byteArray,0,bytesCount);
        }

        inputStream.close();

        byte[] bytes = digest.digest();

        StringBuilder sb = new StringBuilder();
        for (byte aByte : bytes) sb.append(Integer.toString((aByte & 0xFF) + 0X100, 16).substring(1));

        return sb.toString();
    }

    public static String Sign(byte[] bytes, PrivateKey key) throws Exception{

        Signature protectedSignature = Signature.getInstance("SHA256WithRSA");
        protectedSignature.initSign(key);
        protectedSignature.update(bytes);

        byte[] sign = protectedSignature.sign();

        return Base64.getEncoder().encodeToString(sign);
    }

    public static boolean Verify(byte[] bytes, String signature, PublicKey key) throws Exception{

        Signature publicSignature = Signature.getInstance("SHA256WithRSA");
        publicSignature.initVerify(key);
        publicSignature.update(bytes);

        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        return publicSignature.verify(signatureBytes);
    }

    public static KeyPair GenerateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048,new java.security.SecureRandom());
        KeyPair pair = generator.generateKeyPair();

        return pair;
    }

    public static byte[] EncryptWithCertX509(byte[] data, X509Certificate encryptionCertificate) throws CertificateEncodingException, CMSException, IOException {

        byte[] encryptedData = null;
        if (null != data && null != encryptionCertificate) {
            CMSEnvelopedDataGenerator cmsEnvelopedDataGenerator = new CMSEnvelopedDataGenerator();
            JceKeyTransRecipientInfoGenerator jceKey = new JceKeyTransRecipientInfoGenerator(encryptionCertificate);
            cmsEnvelopedDataGenerator.addRecipientInfoGenerator(jceKey);
            CMSTypedData msg = new CMSProcessableByteArray(data);
            OutputEncryptor encryptor = new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider("BC").build();
            CMSEnvelopedData cmsEnvelopedData = cmsEnvelopedDataGenerator.generate(msg,encryptor);
            encryptedData = cmsEnvelopedData.getEncoded();
        }
        return encryptedData;
    }

    public static byte[] DecryptWithCertX509(byte[] encryptedData, PrivateKey decryptionKey) throws CMSException {

        if (null != encryptedData && null != decryptionKey) {
            CMSEnvelopedData envelopedData = new CMSEnvelopedData(encryptedData);

            Collection<RecipientInformation> recipients = envelopedData.getRecipientInfos().getRecipients();
            KeyTransRecipientInformation recipientInfo = (KeyTransRecipientInformation) recipients.iterator().next();
            JceKeyTransRecipient recipient = new JceKeyTransEnvelopedRecipient(decryptionKey);

            return recipientInfo.getContent(recipient);
        }
        return null;
    }

    protected static String getKey(String key) {
       return (key!=null && key.length()>0)?key:DEFAULT_KEY;
    }


    protected static byte[] readFile(File file) throws IOException {
        FileInputStream inputStream = new FileInputStream(file);
        byte[] filedata = new byte[(int)file.length()];
        inputStream.read(filedata);
        inputStream.close();
        return filedata;
    }

    protected static int writeFile( byte[] datatowrite, String outputfile) throws IOException {
        if(datatowrite==null || datatowrite.length==0)
            return -1;

        FileOutputStream ouptutStream = new FileOutputStream(outputfile);
        ouptutStream.write(datatowrite);
        ouptutStream.close();
        return 1;
    }


    public static SecretKeySpec generateKey() {
        final SecureRandom random = new SecureRandom();
        byte[] keyBytes = new byte[KEY_LENGTH];
        random.engineNextBytes(keyBytes);
        return new SecretKeySpec(keyBytes, "AES");
    }



}
