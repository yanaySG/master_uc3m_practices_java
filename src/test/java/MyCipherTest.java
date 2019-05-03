import org.junit.Assert;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.security.KeyPair;
import java.util.Base64;

@FixMethodOrder()
public class MyCipherTest {
    private static final String filename_ref = "transaction_ref.xml";
    private static final String filename = "transaction.xml";
    private static final String filename_enc = "transaction.cpt";
    private static final String filename_add = "additional.txt";

    private static final String key = "MYSECUREPASSWORD";

    @Before
    public void setUp()  {
       MyCipher.Init();
    }

    @Test
    public void testA_EncryptFile() throws Exception{
       Assert.assertEquals(1,MyCipher.EncryptFile(new File(filename),key,filename_enc));
    }

    @Test
    public void testB_DecryptFile() throws Exception{
        Assert.assertEquals(1,MyCipher.DecryptFile(new File(filename_enc),key,filename));
    }

    @Test
    public void testC_EncryptDecryptFile() throws Exception{

        File file = new File(filename);
        File fileadd = new File(filename_add);


        // calculate hash of file before encryption and save it in fileadd
        MyCipher.GetFileChecksum(file, fileadd);
        // get hash from fileadd
        String sha_raw = Base64.getEncoder().encodeToString(MyCipher.readFile(fileadd));


        //encrypt info of file
        MyCipher.EncryptFile(new File(filename),key,filename_enc);

        //decrypt info back to file
        MyCipher.DecryptFile(new File(filename_enc),key,filename);

        // calculate hash of the decrypted info and save it to fileadd
        MyCipher.GetFileChecksum(file,fileadd);
        // read hash from fileadd

        //
        String sha_decrypted = MyCipher.encodeBytes(MyCipher.readFile(fileadd));

        Assert.assertEquals(sha_raw,sha_decrypted);
    }



    @Test
    public void testD_ReadFile() throws IOException{
        Assert.assertEquals(576,MyCipher.readFile(new File(filename_ref)).length);
    }

    @Test
    public void testE_EncryptDecryptBytes() throws Exception{
        byte[] raw_data = MyCipher.readFile(new File(filename_ref));
        byte[] encrypted = MyCipher.encrypt(raw_data,key);
        byte[] decrypted = MyCipher.decrypt(encrypted,key);
        Assert.assertArrayEquals(raw_data,decrypted);
    }


    @Test
    public void testF_GetFileChecksum() throws Exception{
        // calculate hash and save to fileadd
        MyCipher.GetFileChecksum(new File(filename_ref),new File(filename_add));
        // read fileadd
        String sha = MyCipher.encodeBytes(MyCipher.readFile(new File(filename_add)));
        Assert.assertEquals("M2U5NTAyNWYwMmIxMWMzNDgxNDM3Y2RiNDBkNmM1NTNmNzA4NWQyNDY0MGFiZDJmMWU5YmE1YWNhYzU0MGI3Yw==", sha);
    }

    @Test
    public void testH_SignVerifyFile() throws Exception{
        KeyPair pair = MyCipher.GenerateKeyPair();
        byte[] bytes = MyCipher.readFile(new File(filename));
        String signature = MyCipher.SignFileInfo(bytes,pair.getPrivate());

        boolean result = MyCipher.VerifyFileSignature(bytes,signature,pair.getPublic());
        Assert.assertTrue(result);
    }

    @Test
    public void testI_EncryptDecryptWithCertX509() throws Exception{
        byte[] rawdata = MyCipher.readFile(new File(filename));
        byte[] encryptedData = MyCipher.EncryptWithCertX509(rawdata, MyCipher.certificate);
        byte[] decryptedData = MyCipher.DecryptWithCertX509(encryptedData, MyCipher.privateKey);

        Assert.assertArrayEquals(rawdata,decryptedData);
    }


    @Test
    public void testH_EncodeBytes() {
        String encoded = MyCipher.encodeBytes(new byte[] {12,35,65,23,54,76,45,23,67,56,89,12,65,67,89,23,35});
        Assert.assertEquals("DCNBFzZMLRdDOFkMQUNZFyM=",encoded);
    }
}