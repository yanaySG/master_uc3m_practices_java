import org.junit.Assert;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.*;

class MainTest {

    private static final String filename_ref = "transaction_ref.xml";
    private static final String filename = "transaction.xml";
    private static final String filename_enc = "transaction.cpt";
    private static final String filename_add = "additional.txt";

    private static final String key = "MYSECUREPASSWORD";

    //-m se -p MYSECUREPASSWORD -i transaction.xml -o transaction.cpt
    @Test
    void testA_MainWithoutArgs() throws Exception {
           Assert.assertEquals(0, Main.main(new String[]{}));
    }

    @Test
    void testB_MainWithoutAllRequiredArgs() throws Exception {
            Assert.assertEquals(0, Main.main(new String[]{"-m","se"}));
    }

    @Test
    void testC_MainWithAllRequiredArgs() throws Exception {
            Assert.assertEquals(1, Main.main(new String[]{"-m","se","-i",filename}));
    }

    @Test
    void testD_MainWithWrongArgType() throws Exception {
            Assert.assertEquals(0, Main.main(new String[]{"-m","sk","-i",filename}));
    }

    @Test
    void testE_MainWithWrongArgCommand() throws Exception {
            Assert.assertEquals(0, Main.main(new String[]{"-P","se","-i",filename}));
    }

    @Test
    void testF_MainSymmetricEncryptionWithPasswordAndFilename() throws Exception {
        Assert.assertEquals(1, Main.main(new String[]{"-m","se","-p",key,"-i",filename}));
    }


    @Test
    void testG_MainSymmetricDecryptionWithPasswordAndFilename() throws Exception {
        Assert.assertEquals(1, Main.main(new String[]{"-m","sd","-p",key,"-i",filename_enc}));
    }


    @Test
    void testH_MainSymmetricEncryptionDecryptionWithValidPassword() throws Exception {

        // reading raw data from transaction.xml
        String hash_raw=  MyCipher.encodeBytes(MyCipher.readFile(new File(filename)));

        // executing encryption and saving encrypted data into transaction.cpt
        Main.main(new String[]{"-m","se","-p",key,"-i","transaction.xml","-o",filename_enc});

        // executing decryption back into transaction.xml
        Main.main(new String[]{"-m","sd","-p",key,"-i","transaction.cpt","-o",filename});

        // reading decrypted data from transaction.xml
        String hash_decrypted =  MyCipher.encodeBytes(MyCipher.readFile(new File(filename)));

        Assert.assertEquals(hash_raw,hash_decrypted);

    }
}