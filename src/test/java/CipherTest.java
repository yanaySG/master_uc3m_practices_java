
import org.junit.Assert;
import org.junit.Test;

import java.io.File;

public class CipherTest {
    private static String key = "password";
    private static byte[] reference = new byte[]{108,8,-125,-80,33,83,-99,45,-64,16,-52,3,-71,103,107,-42,-52,-2,34,-71,120,88,0,8,93,63,-109,122,-37,-81,-80,94};

    @Test
    public void testEncryptFile() {
        Assert.assertArrayEquals(new byte[]{0,0},Cipher.encryptFile(new File("null"), key));
    }

    @Test
    public void testDecryptFile() {
        Assert.assertNull(Cipher.decryptFile(new byte[]{0,0},key));
    }

    @Test
    public void Encrypt(){
        Assert.assertArrayEquals(reference,Cipher.encryptFile(new File("transaction.xml",key)));
    }
}