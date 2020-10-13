import org.apache.commons.codec.digest.DigestUtils;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import java.io.FileReader;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.BitSet;
import java.util.List;


public class PBKDF2 {
    private final static int NumberOfKeys = 10000;
    private final static int numberOfPasswords = 1000;
    private final static double hmacLen = 32.0;
    private final static int XtsSize = 64;
    private final static int saltSize = 16;
    private final static byte opadValue = 0x5c;
    private final static byte ipadValue = 0x36;
    private final static String passwordsValue = "passwords";
    private static List<byte[]> XORsList = new ArrayList<byte[]>();
    private static byte[] Key = null;


    public static byte[] concateBytes(final byte[] first, final byte[] second) {
        byte[] concatByte = new byte[first.length + second.length];
        System.arraycopy(first, 0, concatByte, 0, first.length);
        System.arraycopy(second, 0, concatByte, first.length, second.length);

        return concatByte;
    }

    public static byte[] concateBytesAndInt(final byte[] first, final byte second) {
        byte[] concatByte = new byte[first.length + 1];
        System.arraycopy(first, 0, concatByte, 0, first.length);
        concatByte[first.length] = second;

        return concatByte;
    }

    public static byte[] HmacSha256 (byte[] XTS, byte[] SKM) {
        byte[] opad = new byte[XTS.length];
        byte[] ipad = new byte[XTS.length];
        byte[] XOROfXTSAndOpad = new byte[XTS.length];
        byte[] XOROfXTSAndIpad = new byte[XTS.length];
        for (int k = 0; k < XTS.length; k++) {
            opad[k] = opadValue;
        }
        for (int m = 0; m < XTS.length; m++) {
            ipad[m] = ipadValue;
        }
        for (int i = 0; i < XTS.length; i++) {
            XOROfXTSAndOpad[i] = (byte) (opad[i] ^ XTS[i]);
        }
        for (int j = 0; j < XTS.length; j++) {
            XOROfXTSAndIpad[j] = (byte) (ipad[j] ^ XTS[j]);
        }
        return DigestUtils.sha256(concateBytes(XOROfXTSAndOpad,
                DigestUtils.sha256(concateBytes(XOROfXTSAndIpad, SKM))));
    }


    public static String JSONReader () throws IOException, ParseException, NoSuchAlgorithmException {
        JSONParser parser = new JSONParser();
        Object obj = parser.parse(new FileReader("C:/Users/georg/Desktop/cryptoLabs/keyGen/passwords.json"));
        JSONObject jsonObject =  (JSONObject) obj;
        JSONArray passwords = (JSONArray) jsonObject.get(passwordsValue);
        int numberOfPasswordsParam = SecureRandom.getInstanceStrong().nextInt(numberOfPasswords);
        return (String) passwords.get(numberOfPasswordsParam);
    }


    public static byte[] PBKDF2Func(byte[] password) throws IOException, NoSuchAlgorithmException {
        byte[] S = new byte[saltSize];
        SecureRandom.getInstanceStrong().nextBytes(S);
        double quantityBlocks = XtsSize / hmacLen;
        quantityBlocks = Math.ceil(quantityBlocks);

        for (int k = 0; k < quantityBlocks; k++) {
            byte kBytes = (byte) k;

            byte[] concatSalt_i = concateBytesAndInt(S, kBytes);
            XORsList.add(0, HmacSha256(password, concatSalt_i));
            byte[] block = XORsList.get(0);
            int counter = 1000;
            for (int i = 1; i < counter; i++) {
                XORsList.add(i, HmacSha256(password, XORsList.get(i-1)));
                for (int j = 0; j < XORsList.get(i).length; j++)
                    block[j] = (byte) (block[j] ^ XORsList.get(i)[j]);
            }
            if (k == 0) {
                Key = block;
            }
            else {
                Key = concateBytes(Key, block);
            }
            XORsList.clear();
        }
        return Key;
    }

    public static void main (String[] args) throws IOException, ParseException, NoSuchAlgorithmException {
        for (int i = 0; i < NumberOfKeys; i++) {
            String password = JSONReader();
            byte[] passwordToBytes = password.getBytes();
            byte[] generatedKey  = PBKDF2Func(passwordToBytes);
            System.out.println(Arrays.toString(generatedKey));
        }
    }
}
