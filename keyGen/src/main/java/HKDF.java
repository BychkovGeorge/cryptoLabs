import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.BitSet;
import java.util.List;
import org.apache.commons.codec.digest.DigestUtils;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

public class HKDF {

    private final static int XtsSize = 32;
    private final static int numberOfWeatherParams = 49;
    private final static int numberOfIterations = 1000;
    private final static byte opadValue = 0x5c;
    private final static byte ipadValue = 0x36;
    private final static String hourlyValue = "hourly";
    private final static String dataValue = "data";
    private final static String windBearingValue = "windBearing";
    private final static String myName = "Bychkov George";

    public HKDF() throws NoSuchAlgorithmException, IOException, ParseException {
    }


    public static byte[] concateBytes(byte[] first, byte[] second) {
        byte[] concatByte = new byte[first.length + second.length];
        System.arraycopy(first, 0, concatByte, 0, first.length);
        System.arraycopy(second, 0, concatByte, first.length, second.length);

        return concatByte;
    }

    public static byte[] concateBytesAndInt(byte[] first, int number) {
        byte second = (byte) number;
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

    public static Long readJSON () throws NoSuchAlgorithmException, IOException, ParseException {
        JSONParser parser = new JSONParser();
        Object obj = parser.parse(new FileReader("C:/Users/georg/Desktop/cryptoLabs/keyGen/weather.json"));
        JSONObject jsonObject =  (JSONObject) obj;
        JSONObject hourly = (JSONObject) jsonObject.get(hourlyValue);
        JSONArray data = (JSONArray) hourly.get(dataValue);
        int numberOfWeatherParam = SecureRandom.getInstanceStrong().nextInt(numberOfWeatherParams);
        JSONObject someData = (JSONObject) data.get(numberOfWeatherParam);
        return (Long) someData.get(windBearingValue);
    }

    public static byte[] HkdfExtract(byte[] XTS, byte[] SKM) throws NoSuchAlgorithmException {
        return HmacSha256(XTS, SKM);
    }

    public static byte[] HkdfExpand(byte[] PRK, byte[] lastKey, byte[] CTX, int i) {
        if (lastKey == null) {
            byte[] CTXinfo = (concateBytesAndInt(CTX, i));
            return HmacSha256(PRK, CTXinfo);
        }
        else {
            byte[] CTXinfo = (concateBytesAndInt(concateBytes(lastKey, CTX), i));
            return HmacSha256(PRK, CTXinfo);
        }
    }

    public static void keyGeneration(byte[] PRK) {
        List<byte[]> massiveOfKeys = new ArrayList<byte[]>();
        for (int i = 0; i < numberOfIterations; i++) {
            if (i == 0) {
                byte[] nameInBytes = myName.getBytes();
                byte[] k = HkdfExpand(PRK, null, nameInBytes, i);
                massiveOfKeys.add(k);
                System.out.println(i + Arrays.toString(k));
            }
            else {
                byte[] nameInBytes = myName.getBytes();
                byte[] keyInBytes = massiveOfKeys.get(i - 1);
                byte[] k = HkdfExpand(PRK, keyInBytes, nameInBytes, i);
                massiveOfKeys.add(k);
                System.out.println(i + Arrays.toString(k));
            }
        }
    }

public static void main (String[] args) throws IOException, ParseException, NoSuchAlgorithmException {
    Long windBearing = readJSON();
    byte[] XTS = new byte[XtsSize];
    SecureRandom.getInstanceStrong().nextBytes(XTS);
    byte[] SKM = windBearing.toString().getBytes();
    byte[] PRK = HkdfExtract(XTS, SKM);
    keyGeneration(PRK);
    }

}



