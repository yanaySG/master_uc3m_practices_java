import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;

import java.io.File;
import java.io.FileInputStream;

public class Cipher {

    static BlockCipher engine = new AESEngine();

    public static byte[] Encrypt(byte[] plainText, String key) throws InvalidCipherTextException {

        byte[] ptBytes = plainText;
        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(engine));
        cipher.init(true, new KeyParameter(key.getBytes()));
        byte[] rv = new byte[cipher.getOutputSize(ptBytes.length)];
        int tam = cipher.processBytes(ptBytes, 0, ptBytes.length, rv, 0);
        cipher.doFinal(rv, tam);

        return rv;
    }

    public static byte[] Decrypt(byte[] cipherText,String key) throws InvalidCipherTextException{

        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(engine));
        cipher.init(false, new KeyParameter(key.getBytes()));
        byte[] rv = new byte[cipher.getOutputSize(cipherText.length)];
        int tam = cipher.processBytes(cipherText, 0, cipherText.length, rv, 0);
        cipher.doFinal(rv, tam);

        return rv;
    }

    public static byte[] encryptFile(File file, String... password) throws Exception{

        FileInputStream inputStream = new FileInputStream(file);
        byte filedata[] = new byte[(int)file.length()];
        inputStream.read(filedata);
        Encrypt(filedata,password[0]);


        return new byte[]{0,0};
    }

    public static File decryptFile( byte[] filestream, String... password){
        return null;
    }


}
