import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.operator.OutputEncryptor;
import sun.security.provider.SecureRandom;

import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;

import static java.nio.charset.StandardCharsets.UTF_8;

public class MyCipher {

    static int INPUT_LENGTH = 1024;
    static int OUTPUT_LENGTH = 1024;
    static int KEY_LENGTH = 16;
    static String DEFAULT_KEY = "ASDFGHJKLASDFGHJ";


    public static byte[] Encrypt(byte[] plainText, String key) throws InvalidCipherTextException {

        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()));
        cipher.init(true,new KeyParameter(key.getBytes()));
        byte[] rv = new byte[cipher.getOutputSize(plainText.length)];
        int tam = cipher.processBytes(plainText, 0, plainText.length, rv, 0);
        cipher.doFinal(rv, tam);
        INPUT_LENGTH  = rv.length;
        return rv;
    }

    public static byte[] Decrypt(byte[] cipherText,String key) throws InvalidCipherTextException{

        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()));
        cipher.init(false, new KeyParameter(key.getBytes()));
        byte[] rv = new byte[cipher.getOutputSize(cipherText.length)];
        int tam = cipher.processBytes(cipherText, 0, cipherText.length, rv, 0);
        cipher.doFinal(rv, tam);
        OUTPUT_LENGTH  = rv.length;
        return rv;
    }

    public static int decryptFile(File file, String key) throws IOException, InvalidCipherTextException{
        if(file==null || !file.exists())
            return -1;

        byte[] encrypteddata = readFile(file);
        byte[] decrypteddata  = Decrypt(encrypteddata,key);
        final String decryptedVal = new String(decrypteddata);
        System.out.println(decryptedVal);
        return writeFile(file,decrypteddata,".encrypted",".xml");
    }

    public static int encryptFile(File file, String key) throws IOException, InvalidCipherTextException{
        if(file==null || !file.exists())
            return -1;

        byte[] encrypteddata = Encrypt(readFile(file),getKey(key));
        return writeFile(file,encrypteddata,".xml",".encrypted");
    }

    private static String getKey(String key) {
       return (key!=null && key.length()>0)?key:DEFAULT_KEY;
    }

    public static byte[] readFile(File file) throws IOException {
        FileInputStream inputStream = new FileInputStream(file);
        byte[] filedata = new byte[(int)file.length()];
        inputStream.read(filedata);
        inputStream.close();
        return filedata;
    }

    public static int writeFile(File file, byte[] datatowrite, String oldExtension, String newExtension) throws IOException {
        if(file==null || !file.exists())
            return -1;

        FileOutputStream ouptutStream = new FileOutputStream(getFileName(file, oldExtension, newExtension));
        ouptutStream.write(datatowrite);
        ouptutStream.close();
        return 1;
    }

    public static String getFileName(File file, String oldExtension, String newExtension) {
        return file.getName().replace(oldExtension,newExtension);
    }

    public static String getFileChecksum(File file) throws IOException, NoSuchAlgorithmException {
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

        Signature privateSignature = Signature.getInstance("SHA256WithRSA");
        privateSignature.initSign(key);
        privateSignature.update(bytes);

        byte[] sign = privateSignature.sign();

        return Base64.getEncoder().encodeToString(sign);
    }

    public static boolean Verify(byte[] bytes, String signature, PublicKey key) throws Exception{

        Signature publicSignature = Signature.getInstance("SHA256WithRSA");
        publicSignature.initVerify(key);
        publicSignature.update(bytes);

        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        return publicSignature.verify(signatureBytes);
    }

    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048,new java.security.SecureRandom());
        KeyPair pair = generator.generateKeyPair();

        return pair;
    }

    public static SecretKeySpec generateKey() {
        final SecureRandom random = new SecureRandom();
        byte[] keyBytes = new byte[KEY_LENGTH];
        random.engineNextBytes(keyBytes);
        return new SecretKeySpec(keyBytes, "AES");
    }

    public static byte[] encryptWithCertX509(byte[] data, X509Certificate encryptionCertificate) throws CertificateEncodingException, CMSException, IOException {

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

    public static byte[] decryptWithCertX509(byte[] encryptedData, PrivateKey decryptionKey) throws CMSException {

        if (null != encryptedData && null != decryptionKey) {
            CMSEnvelopedData envelopedData = new CMSEnvelopedData(encryptedData);

            Collection<RecipientInformation> recipients = envelopedData.getRecipientInfos().getRecipients();
            KeyTransRecipientInformation recipientInfo = (KeyTransRecipientInformation) recipients.iterator().next();
            JceKeyTransRecipient recipient = new JceKeyTransEnvelopedRecipient(decryptionKey);

            return recipientInfo.getContent(recipient);
        }
        return null;
    }


}
