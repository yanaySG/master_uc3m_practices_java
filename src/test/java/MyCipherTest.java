import org.junit.Assert;
import org.junit.Test;

import java.io.File;
import java.io.IOException;

public class MyCipherTest {
    private static File file = new File("transaction.xml");
    private static File file_enc = new File("transaction.encrypted");
   // private static String key = "ASDFGHJKLASDFGHJ";
    private static String key = "MYSECUREPASSWORD";

    @Test
    public void testEncryptFile() throws Exception{
       Assert.assertEquals(1,MyCipher.encryptFile(file,key));
    }

    @Test
    public void testDecryptFile() throws Exception{
        Assert.assertEquals(1,MyCipher.decryptFile(file_enc,key));
    }

    @Test
    public void readFile() throws IOException{
            Assert.assertEquals(528,MyCipher.readFile(file).length);
    }

    @Test
    public void Encrypt() throws Exception{
        byte[] readdata = MyCipher.readFile(file);
        Assert.assertEquals(544, MyCipher.Encrypt(readdata,key).length);
    }
}