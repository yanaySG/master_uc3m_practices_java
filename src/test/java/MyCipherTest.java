import org.junit.Assert;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import java.io.File;
import java.io.IOException;
import java.security.KeyPair;

@FixMethodOrder()
public class MyCipherTest {
    private static final String filename_ref = "transaction_ref.xml";
    private static final String filename = "transaction.xml";
    private static final String filename_enc = "transaction.cpt";

    private static final String key = "MYSECUREPASSWORD";

    @Before
    public void setUp()  {
       MyCipher.Init();
    }

    @Test
    public void testAEncryptFile() throws Exception{
       Assert.assertEquals(1,MyCipher.EncryptFile(new File(filename),key,filename_enc));
    }

    @Test
    public void testBDecryptFile() throws Exception{
        Assert.assertEquals(1,MyCipher.DecryptFile(new File(filename_enc),key,filename));
    }

    @Test
    public void testCEncryptDecryptFile() throws Exception{
        File file = new File(filename);
        String sha_raw = MyCipher.GetFileChecksum(file);
        MyCipher.EncryptFile(new File(filename),key,filename_enc);

        MyCipher.DecryptFile(new File(filename_enc),key,filename);
        String sha_decrypted = MyCipher.GetFileChecksum(file);

        Assert.assertEquals(sha_raw,sha_decrypted);
    }

    @Test
    public void testDReadFile() throws IOException{
        Assert.assertEquals(576,MyCipher.readFile(new File(filename_ref)).length);
    }

    @Test
    public void testEEncryptDecryptBytes() throws Exception{
        byte[] raw_data = MyCipher.readFile(new File(filename_ref));
        byte[] encrypted = MyCipher.encrypt(raw_data,key);
        byte[] decrypted = MyCipher.decrypt(encrypted,key);
        Assert.assertArrayEquals(raw_data,decrypted);
    }


    @Test
    public void testFGetFileChecksum() throws Exception{
        Assert.assertEquals("3e95025f02b11c3481437cdb40d6c553f7085d24640abd2f1e9ba5acac540b7c",
                MyCipher.GetFileChecksum(new File(filename_ref)));
    }

    @Test
    public void testHSignVerifyFile() throws Exception{
        KeyPair pair = MyCipher.GenerateKeyPair();
        byte[] bytes = MyCipher.readFile(new File(filename));
        String signature = MyCipher.Sign(bytes,pair.getPrivate());

        boolean result = MyCipher.Verify(bytes,signature,pair.getPublic());
        Assert.assertTrue(result);
    }

    @Test
    public void testIEncryptDecryptWithCertX509() throws Exception{
        byte[] rawdata = MyCipher.readFile(new File(filename));
        byte[] encryptedData = MyCipher.EncryptWithCertX509(rawdata, MyCipher.certificate);
        byte[] decryptedData = MyCipher.DecryptWithCertX509(encryptedData, MyCipher.privateKey);

        Assert.assertArrayEquals(rawdata,decryptedData);
    }
}