package george;

import javax.crypto.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;


public class AesBlockEncrypt {

    public static final String cipherModeNoPadding = "AES/ECB/NoPadding";
    public static final String cipherModePlusPKCS5Padding = "AES/ECB/NoPadding";

    public static byte[] concateBytes(byte[] first, byte[] second) {
        byte[] concatByte = new byte[first.length + second.length];
        System.arraycopy(first, 0, concatByte, 0, first.length);
        System.arraycopy(second, 0, concatByte, first.length, second.length);

        return concatByte;
    }


    public static byte[] aesBlockEncrypt(SecretKey key, byte[] data, boolean isFinalBLock, String paddingType) throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchProviderException {
        if (isFinalBLock) {
            Cipher aesCipher = Cipher.getInstance(paddingType);
            aesCipher.init(Cipher.ENCRYPT_MODE, key);
            return aesCipher.doFinal(data);
        }
        else {
            Cipher aesCipher = Cipher.getInstance(cipherModeNoPadding);
            aesCipher.init(Cipher.ENCRYPT_MODE, key);
            return aesCipher.doFinal(data);
        }
    }
}