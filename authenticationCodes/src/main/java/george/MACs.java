package george;


import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.BitSet;
import java.util.List;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;


import static george.AesBlockEncrypt.aesBlockEncrypt;
import static george.AesBlockEncrypt.concateBytes;

public class MACs {

    public static final int blockSize = 16;
    public static final String cipherModeNoPadding = "AES/ECB/NoPadding";
    public static final String cipherModePKCS5Padding = "AES/ECB/PKCS5Padding";
    public static final String algorithm = "AES";
    public static final String algorithmHMACName = "HMAC";
    public static final String algorithmTruncatedMACName = "truncated-MAC";
    public static final String algorithmOMACName = "OMAC";
    private final static byte opadValue = 0x5c;
    private final static byte ipadValue = 0x36;

    public byte[] Rn;
    public SecretKey secretKey;
    public String mode;
    public String paddingMode;
    public List<byte[]> blocksToUse;

    public MACs(String mode) throws NoSuchAlgorithmException {
        this.secretKey = null;
        this.mode = mode;
        this.blocksToUse = new ArrayList<byte[]>();
        this.Rn = new byte[blockSize];
        SecureRandom.getInstanceStrong().nextBytes(Rn);
        if (this.mode.equals(algorithmOMACName)) {
            this.paddingMode = cipherModePKCS5Padding;
        }
        else if (this.mode.equals(algorithmTruncatedMACName)) {
            this.paddingMode = cipherModePKCS5Padding;
        }
        else if (this.mode.equals(algorithmHMACName)) {
            this.paddingMode = cipherModeNoPadding;
        }
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

    public void setKey(byte[] key) {
        this.secretKey = new SecretKeySpec(key, algorithm);
    }

    public void macAddBlock(byte[] dataBlock) {
        this.blocksToUse.add(dataBlock);
    }

    public byte[] macFinalize() throws Exception {
        if (!this.mode.equals(algorithmOMACName) && !this.mode.equals(algorithmHMACName) && !this.mode.equals(algorithmTruncatedMACName)) {
            throw new Exception("InvalidMACAlgorithm");
        }
        switch (this.mode) {
            case "OMAC": {
                byte[] k1 = new byte[this.secretKey.getEncoded().length];
                byte[] k2 = new byte[this.secretKey.getEncoded().length];
                byte[] k3 = new byte[this.secretKey.getEncoded().length];
                byte[] L = new byte[this.secretKey.getEncoded().length];
                byte[] zeroByteArray = new byte[this.secretKey.getEncoded().length];
                SecretKey zeroKey = new SecretKeySpec(zeroByteArray, algorithm);
                k1 = secretKey.getEncoded();
                L = aesBlockEncrypt(zeroKey, k1, false, cipherModeNoPadding);
                BitSet bitSet = BitSet.valueOf(L);
                if (!bitSet.get(0)) {
                    boolean temp = bitSet.get(0);
                    for (int i = 0; i < bitSet.size(); i++) {
                        if (i != bitSet.size() - 1) {
                            bitSet.set(i, bitSet.get(i + 1));
                        }
                        else {
                            bitSet.set(i, temp);
                        }
                    }
                    k2 = bitSet.toByteArray();
                }
                else  {
                    boolean temp = bitSet.get(0);
                    for (int i = 0; i < bitSet.size(); i++) {
                        if (i != bitSet.size() - 1) {
                            bitSet.set(i, bitSet.get(i + 1));
                        }
                        else {
                            bitSet.set(i, temp);
                        }
                    }
                    byte[] tmp = bitSet.toByteArray();
                    for (int i = 0; i < k2.length; i++) {
                        k2[i] = (byte) (tmp[i] ^ this.Rn[i]);
                    }
                }
                BitSet newBitSet = BitSet.valueOf(k2);
                if (!newBitSet.get(0)) {
                    boolean temp = newBitSet.get(0);
                    for (int i = 0; i < newBitSet.size(); i++) {
                        if (i != newBitSet.size() - 1) {
                            newBitSet.set(i, newBitSet.get(i + 1));
                        }
                        else {
                            newBitSet.set(i, temp);
                        }
                    }
                    k3 = newBitSet.toByteArray();
                }
                else  {
                    boolean temp = newBitSet.get(0);
                    for (int i = 0; i < newBitSet.size(); i++) {
                        if (i != newBitSet.size() - 1) {
                            newBitSet.set(i, newBitSet.get(i + 1));
                        }
                        else {
                            newBitSet.set(i, temp);
                        }
                    }
                    byte[] tmp = newBitSet.toByteArray();
                    for (int i = 0; i < tmp.length; i++) {
                        k3[i] = (byte) (tmp[i] ^ this.Rn[i]);
                    }
                }
                byte[] temp = new byte[blockSize];
                boolean isFinalBlock = false;
                for (int i = 0; i < this.blocksToUse.size(); i++) {
                    if (i == 0) {
                        temp = aesBlockEncrypt(this.secretKey, this.blocksToUse.get(i), isFinalBlock, this.paddingMode);
                    }
                    else if (i == this.blocksToUse.size() - 1) {
                        isFinalBlock = true;
                        byte[] tmp = new byte[blockSize];
                        for (int j = 0; j < temp.length; j++) {
                            tmp[j] = (byte) (this.blocksToUse.get(i)[j] ^ temp[j]);
                        }
                        if (this.blocksToUse.get(i).length == blockSize) {
                            for (int j = 0; j < k2.length; j++) {
                                tmp[j] = (byte) (tmp[j] ^ k2[j]);
                            }
                        }
                        else if (this.blocksToUse.get(i).length < blockSize) {
                            for (int j = 0; j < tmp.length; j++) {
                                tmp[j] = (byte) (tmp[j] ^ k3[j]);
                            }
                        }
                        temp = aesBlockEncrypt(this.secretKey, tmp, isFinalBlock, this.paddingMode);
                    }
                    else {
                        byte[] tmp = new byte[blockSize];
                        for (int j = 0; j < temp.length; j++) {
                            tmp[j] = (byte) (temp[j] ^ this.blocksToUse.get(i)[j]);
                        }
                        temp = aesBlockEncrypt(this.secretKey, tmp, isFinalBlock, this.paddingMode);
                    }
                }
                return temp;
            }
            case "truncated-MAC": {
                byte[] temp = new byte[blockSize];
                boolean isFinalBlock = false;
                for (int i = 0; i < this.blocksToUse.size(); i++) {
                    if (i == this.blocksToUse.size() - 1) {
                        isFinalBlock = true;
                    }
                    if (i == 0) {
                        byte[] zeroBlock = new byte[blockSize];
                        byte[] tmp = new byte[blockSize];
                        for (int j = 0; j < tmp.length; j++) {
                            tmp[j] = (byte) (this.blocksToUse.get(i)[j] ^ zeroBlock[j]);
                        }
                        temp = aesBlockEncrypt(this.secretKey, tmp, isFinalBlock, this.paddingMode);
                    }
                    else {
                        byte[] tmp = new byte[blockSize];
                        for (int j = 0; j < tmp.length; j++) {
                            tmp[j] = (byte) (this.blocksToUse.get(i)[j] ^ temp[j]);
                        }
                        temp = aesBlockEncrypt(this.secretKey, tmp, isFinalBlock, this.paddingMode);
                    }
                }
                byte[] res = new byte[blockSize / 2];
                for (int i = 0; i < res.length; i++) {
                    res[i] = temp[i];
                }
                return res;
            }
            case "HMAC": {
                byte[] opad = new byte[blockSize];
                byte[] ipad = new byte[blockSize];
                Arrays.fill(opad, opadValue);
                Arrays.fill(ipad, ipadValue);
                byte[] xorOfIpadAndKey = new byte[ipad.length];
                byte[] xorOfOpadAndKey = new byte[opad.length];
                for (int i = 0; i < xorOfIpadAndKey.length; i++) {
                    xorOfIpadAndKey[i] = (byte) (ipad[i] ^ this.secretKey.getEncoded()[i]);
                }
                for (int i = 0; i < xorOfOpadAndKey.length; i++) {
                    xorOfOpadAndKey[i] = (byte) (opad[i] ^ this.secretKey.getEncoded()[i]);
                }
                return DigestUtils.sha256(concateBytes(xorOfOpadAndKey, DigestUtils.sha256(
                        concateBytes(xorOfIpadAndKey, this.blocksToUse.get(0)))));
            }
            default: {
                return null;
            }
        }
    }

    public byte[] computeMac(byte[] data) throws Exception {
        if (!this.mode.equals(algorithmHMACName)) {
            this.bytesToBlocks(data);
        }
        else {
            this.blocksToUse.add(data);
        }
        byte[] res = this.macFinalize();
        this.blocksToUse.clear();
        return res;
    }

    public boolean verifyMac(byte[] data, byte[] tag) throws Exception {
        return Arrays.equals(this.computeMac(data), tag);
    }
}
