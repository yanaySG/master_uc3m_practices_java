import org.junit.Assert;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.security.KeyPair;

import static java.nio.charset.StandardCharsets.UTF_8;

public class MyCipherTest {
    private static final File file = new File("transaction.xml");
    private static final File file_ref = new File("transaction_ref.xml");
    private static final File file_enc = new File("transaction.encrypted");
    private static final String key = "MYSECUREPASSWORD";

    @Test
    public void testEncryptFile() throws Exception{
       Assert.assertEquals(1,MyCipher.encryptFile(file,key));
    }

    @Test
    public void testDecryptFile() throws Exception{
        Assert.assertEquals(1,MyCipher.decryptFile(file_enc,key));
    }

    @Test
    public void testEncryptDecryptFile() throws Exception{
        String sha_raw = MyCipher.getFileChecksum(file);
        MyCipher.encryptFile(file,key);
        String sha_encrypted = MyCipher.getFileChecksum(file_enc);
        MyCipher.decryptFile(file_enc,key);
        String sha_decrypted = MyCipher.getFileChecksum(file);

        Assert.assertEquals(sha_raw,sha_decrypted);
    }

    @Test
    public void testReadFile() throws IOException{
        Assert.assertEquals(576,MyCipher.readFile(file_ref).length);
    }

    @Test
    public void testEncryptDecryptBytes() throws Exception{
        byte[] raw_data = MyCipher.readFile(file);
        byte[] encrypted = MyCipher.Encrypt(raw_data,key);
        byte[] decrypted = MyCipher.Decrypt(encrypted,key);
        Assert.assertArrayEquals(raw_data,decrypted);
    }


    @Test
    public void testGetFileChecksum() throws Exception{
        Assert.assertEquals("3e95025f02b11c3481437cdb40d6c553f7085d24640abd2f1e9ba5acac540b7c",
                MyCipher.getFileChecksum(file_ref));
    }

    @Test
    public void testSignVerifyFile() throws Exception{
        KeyPair pair = MyCipher.generateKeyPair();
        byte[] bytes = MyCipher.readFile(file);
        String signature = MyCipher.Sign(bytes,pair.getPrivate());

        boolean result = MyCipher.Verify(bytes,signature,pair.getPublic());
        Assert.assertTrue(result);
    }
}