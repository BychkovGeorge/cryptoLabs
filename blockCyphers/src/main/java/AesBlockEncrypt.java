import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;


public class AesBlockEncrypt {

    public static final String cipherMode = "AES";

    public static byte[] concateBytes(byte[] first, byte[] second) {
        byte[] concatByte = new byte[first.length + second.length];
        System.arraycopy(first, 0, concatByte, 0, first.length);
        System.arraycopy(second, 0, concatByte, first.length, second.length);

        return concatByte;
    }


    public static byte[] aesBlockEncrypt(byte[] key, byte[] data, boolean isFinalBLock, String padding) throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {
        if (isFinalBLock) {
            byte[] paddingInBytes = padding.getBytes();
            data = concateBytes(data, paddingInBytes);
        }
        byte[] resultBytesArray = new byte[data.length];
        Cipher cipher = Cipher.getInstance(cipherMode);
        for (int i = 0; i < data.length; i++) {
            resultBytesArray[i] = (byte) (data[i] ^ key[i]);
        }
        return cipher.doFinal(resultBytesArray);
    }

}
