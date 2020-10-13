package george;

import org.apache.commons.codec.digest.DigestUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.apache.commons.codec.binary.Hex;



import static george.AesBlockEncrypt.*;
import static george.AesBlockEncrypt.concateBytes;

public class AuthenticatedEncryption {
    public static final int blockSize = 16;
    public static final int dataSize = 104857600;
    public static final String paddingType = "AES/ECB/NoPadding";
    public static final String algorithm = "AES";
    public static final String encryptMode = "ENCRYPT";
    public static final String decryptMode = "DECRYPT";
    private final static byte opadValue = 0x5c;
    private final static byte ipadValue = 0x36;

    public List<byte[]> blocksToUse;
    public SecretKey secretKey;
    public SecretKey secretMacKey;
    public String mode;


    public AuthenticatedEncryption(String mode){
        this.secretKey = null;
        this.secretMacKey = null;
        this.blocksToUse = new ArrayList<byte[]>();
        this.mode = mode;
    }


    public void bytesToBlocks(byte[] bytesArray) {
        int counter = 0;
        while (counter < (bytesArray.length - (bytesArray.length % blockSize)) / blockSize) {
            byte[] temp = new byte[blockSize];
            for (int i = counter * blockSize; i < counter * blockSize + blockSize; i++) {
                temp[i - counter * blockSize] = bytesArray[i];
            }
            this.macAddBlock(temp);
            counter++;
        }
        if (bytesArray.length % blockSize == 0) {
            return;
        }
        else {
            byte[] temp = new byte[bytesArray.length % blockSize];
            for (int i = counter * blockSize; i < bytesArray.length; i++) {
                temp[i - counter * blockSize] = bytesArray[i];
            }
            this.macAddBlock(temp);
            return;
        }
    }


    public byte[] CTREncrypt() throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchProviderException, NoSuchPaddingException {
        byte[] result = new byte[0];
        boolean isFinalBlock = false;
        List<byte[]> listOfCiphers = new ArrayList<byte[]>();
        byte[] Nonce = new byte[blockSize];
        SecureRandom.getInstanceStrong().nextBytes(Nonce);
        this.blocksToUse.add(0, Nonce);
        for (int i = 1; i < this.blocksToUse.size(); i++) {
            if (i == this.blocksToUse.size() - 1) {
                isFinalBlock = true;
            }
            byte[] temp = new byte[blockSize];
            if (i != 1) {
                int increase;
                increase = ((int) this.blocksToUse.get(0)[this.blocksToUse.get(0).length - 1]) + 1;
                this.blocksToUse.get(0)[this.blocksToUse.get(0).length - 1] = (byte) increase;
            }
            for (int j = 0; j < this.blocksToUse.get(i).length; j++) {
                temp[j] = (byte) (this.blocksToUse.get(i)[j] ^ aesBlockEncrypt(this.secretKey, this.blocksToUse.get(0), isFinalBlock, paddingType)[j]);
            }
            listOfCiphers.add(temp);
        }
        for (int i = 0; i < listOfCiphers.size(); i++) {
            if (i == 0) {
                result = concateBytes(result, Nonce);
            }
            result = concateBytes(result, listOfCiphers.get(i));
        }
        return result;
    }


    public byte[] CTRDecrypt() throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidKeyException {
        byte[] result = new byte[0];
        boolean isFinalBlock = false;
        List<byte[]> listOfCiphers = new ArrayList<byte[]>();
        for (int i = 1; i < this.blocksToUse.size(); i++) {
            if (i == this.blocksToUse.size() - 1) {
                isFinalBlock = true;
            }
            byte[] temp = new byte[blockSize];
            if (i != 1) {
                int increase;
                increase = ((int) this.blocksToUse.get(0)[this.blocksToUse.get(0).length - 1]) + 1;
                this.blocksToUse.get(0)[this.blocksToUse.get(0).length - 1] = (byte) increase;
            }
            for (int j = 0; j < this.blocksToUse.get(i).length; j++) {
                temp[j] = (byte) (this.blocksToUse.get(i)[j] ^ aesBlockDecrypt(this.secretKey, this.blocksToUse.get(0), isFinalBlock, paddingType)[j]);
            }
            listOfCiphers.add(temp);
        }
        for (int i = 0; i < listOfCiphers.size(); i++) {
            result = concateBytes(result, listOfCiphers.get(i));
        }
        return result;
    }


    public void macAddBlock(byte[] dataBlock) {
        this.blocksToUse.add(dataBlock);
    }


    public void setKey(byte[] key) {
        this.secretKey = new SecretKeySpec(key, algorithm);
    }

    public void setMacKey(byte[] key) {
        this.secretMacKey = new SecretKeySpec(key, algorithm);
    }


    public byte[] computeMac(byte[] data) throws Exception {
        this.blocksToUse.clear();
        this.blocksToUse.add(0, data);
        byte[] res = this.macFinalize();
        this.blocksToUse.clear();
        return res;
    }


    public byte[] macFinalize() {
        byte[] opad = new byte[blockSize];
        byte[] ipad = new byte[blockSize];
        Arrays.fill(opad, opadValue);
        Arrays.fill(ipad, ipadValue);
        byte[] xorOfIpadAndKey = new byte[ipad.length];
        byte[] xorOfOpadAndKey = new byte[opad.length];
        for (int i = 0; i < xorOfIpadAndKey.length; i++) {
            xorOfIpadAndKey[i] = (byte) (ipad[i] ^ this.secretMacKey.getEncoded()[i]);
        }
        for (int i = 0; i < xorOfOpadAndKey.length; i++) {
            xorOfOpadAndKey[i] = (byte) (opad[i] ^ this.secretMacKey.getEncoded()[i]);
        }
        return DigestUtils.sha256(concateBytes(xorOfOpadAndKey, DigestUtils.sha256(
                concateBytes(xorOfIpadAndKey, this.blocksToUse.get(0)))));
    }


    public byte[] processData(byte[] data) throws Exception {
        this.bytesToBlocks(data);
        if (this.mode.equals(encryptMode)) {
            byte[] res = this.CTREncrypt();
            byte[] mac = this.computeMac(res);
            if (!this.verifyMac(res, mac)){
                throw new Exception("InvalidMac");
            }
            System.out.println(mac.length);
            return concateBytes(res, mac);
        }
        else if (this.mode.equals(decryptMode)) {
            byte[] res = this.CTRDecrypt();
            byte[] mac = this.computeMac(res);
            if (!this.verifyMac(res, mac)){
                throw new Exception("InvalidMac");
            }
            return concateBytes(res, mac);
        }
        else {
            throw new Exception("InvalidMode");
        }
    }

    public boolean verifyMac(byte[] data, byte[] tag) throws Exception {
        return Arrays.equals(this.computeMac(data), tag);
    }


    public static void main(String[] args) throws Exception {
        byte[]  data = new byte[dataSize];
        SecureRandom.getInstanceStrong().nextBytes(data);
        System.out.println(Hex.encodeHexString(data));

        byte[] key = new byte[blockSize];
        SecureRandom.getInstanceStrong().nextBytes(key);

        byte[] key1 = new byte[blockSize];
        SecureRandom.getInstanceStrong().nextBytes(key1);

        AuthenticatedEncryption authenticatedEncryption = new AuthenticatedEncryption(encryptMode);

        authenticatedEncryption.setKey(key);
        authenticatedEncryption.setMacKey(key1);

        byte[] res = authenticatedEncryption.processData(data);
        System.out.println(Hex.encodeHexString(res));
    }
}
