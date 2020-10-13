import org.apache.commons.codec.digest.DigestUtils;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;

public class BirthdayParadoxAttack {
    public static Map<byte[], byte[]> storage = new HashMap<byte[], byte[]>();
    public static Map<Set<byte[]>, Set<byte[]>> answer = new HashMap<>();
    public static final int keySize = 64;
    public static final int hashSize = 15;
    public static final int numberOfCollisions = 100;
    public static final int weightOfElementsInMap = 67;
    public static final String sizeMessage = "size of map = ";
    public static final String timeMessage = "total time - ";
    public static final String bytesMessage = " bytes";
    public static final String formatHexadecimal = "%02x";

    public static void toHexString(byte[] hash) {
        StringBuilder stringBuilder = new StringBuilder();
        for (byte hashInByte : hash) {
            stringBuilder.append(String.format(formatHexadecimal, hashInByte));
        }
        System.out.println(stringBuilder.toString());
    }

    public static void main (String[] args) throws NoSuchAlgorithmException, NullPointerException{
        boolean endOfCycle = false;
        int counter = 0;
        long start = System.currentTimeMillis();
        try {
            while (true) {
                byte[] key = new byte[keySize];
                SecureRandom.getInstanceStrong().nextBytes(key);
                byte[] hashedKey = DigestUtils.sha256(key);
                byte[] smallHashedKey = null;
                BitSet bitSet = BitSet.valueOf(hashedKey);
                BitSet smallBitSet = new BitSet(hashSize);
                for (int i = 0; i < hashSize; i++) {
                    if (bitSet.get(i)) {
                        smallBitSet.set(i);
                    }
                    else {
                        smallBitSet.set(i, false);
                    }
                }
                smallHashedKey = smallBitSet.toByteArray();
                if (!storage.isEmpty()) {
                    for (byte[] entry : storage.keySet()) {
                            if (Arrays.equals(storage.get(entry), smallHashedKey) && !Arrays.equals(entry, key)) {
                                Set<byte[]> setOfHashes = new HashSet<>();
                                setOfHashes.add(smallHashedKey);
                                setOfHashes.add(storage.get(entry));
                                Set<byte[]> setOfKeys = new HashSet<>();
                                setOfKeys.add(entry);
                                setOfKeys.add(key);
                                answer.put(setOfKeys, setOfHashes);
                                counter++;
                            }
                            if (counter == numberOfCollisions) {
                                endOfCycle = true;
                            }
                    }
                }
                if (!storage.containsKey(key)) {
                    storage.put(key, smallHashedKey);
                }

                if (endOfCycle) {
                    break;
                }
            }
        }catch (NullPointerException e){
            System.out.println("error");
        }
        long end = System.currentTimeMillis();
        for (Set<byte[]> entry: answer.keySet()) {
            for (byte[] k : entry) {
                toHexString(k);
            }
            for (byte[] b : answer.get(entry)) {
               toHexString(b);
            }
            System.out.println();
        }
        System.out.println(sizeMessage + weightOfElementsInMap * storage.size() + bytesMessage);
        System.out.println(timeMessage + (end - start));
    }
}
