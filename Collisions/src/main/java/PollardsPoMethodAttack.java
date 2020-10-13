import org.apache.commons.codec.digest.DigestUtils;

import javax.swing.*;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;

public class PollardsPoMethodAttack {

    public static Map<Integer, Map<Boolean, byte[]>> memory = new HashMap<>();
    public static final int keySize = 64;
    public static final int hashSize = 13;
    public static final int countOfZeros = 4;
    public static final int numberOfCollisions = 100;
    public static final int weightOfElement = 17;
    public static int iter = 1;
    public static boolean endOfCycle = false;
    public static int numberOfComparing = 0;
    public static byte[] operOne;
    public static byte[] operTwo;
    public static double totalTime = 0;
    public static double totalMemory = 0;
    public static final String formatHexadecimal = "%02x";


    public static void toHexString(byte[] hash) {
        StringBuilder stringBuilder = new StringBuilder();
        for (byte hashInByte : hash) {
            stringBuilder.append(String.format(formatHexadecimal, hashInByte));
        }
        System.out.println(stringBuilder.toString());
    }

    public static byte[] Pi(byte[] bytesArray) {
        BitSet bitSet;
        bitSet = BitSet.valueOf(bytesArray);
        BitSet newBitSet = new BitSet(bitSet.size() + countOfZeros);
        for (int i = 0; i < newBitSet.size(); i++) {
            if (i < bitSet.size()) {
                if (bitSet.get(i)) {
                    newBitSet.set(i);
                }
                else {
                    newBitSet.set(i, false);
                }
            }
            else {
                newBitSet.set(i, false);
            }
        }
        return newBitSet.toByteArray();
    }

    public static byte[] myHashFunc(byte[] bytesArray) {
        byte[] bigHash = DigestUtils.sha256(bytesArray);
        byte[] smallHash;
        BitSet bitSet = BitSet.valueOf(bigHash);
        BitSet smallBitSet = new BitSet(hashSize);
        for (int o = 0; o < hashSize; o++) {
            if (bitSet.get(o)) {
                smallBitSet.set(o);
            }
            else {
                smallBitSet.set(o, false);
            }
        }
        smallHash = smallBitSet.toByteArray();
        return Pi(smallHash);
    }

    public static boolean isDistinguishedPoint(byte[] bytesArray) {
        int q = hashSize / 2 - 1;
        int c = 0;
        BitSet bitSetOne;
        bitSetOne = BitSet.valueOf(bytesArray);
        for (int x = 0; x < q; x++) {
            if (bitSetOne.get(x)) {
                c++;
            }
        }
        return c == 0;
    }

    public static byte[] thread(Map<Boolean, byte[]> eternalMap, byte[] bytes, Boolean threadIdentifier) {
       byte[] nextValue = myHashFunc(bytes);
       int counter = 0;
        if (isDistinguishedPoint(nextValue)) {
            counter++;
            for (int entry : memory.keySet()) {
                if (memory.get(entry).containsKey(!threadIdentifier)) {
                    if (Arrays.equals(nextValue, memory.get(entry).get(!threadIdentifier))) {
                        endOfCycle = true;
                        numberOfComparing = entry;
                    }
                }
            }
        }
        if (counter == 1) {
            eternalMap.put(threadIdentifier, nextValue);
        }
        return nextValue;
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        for (int i = 0; i < numberOfCollisions; i++) {
            endOfCycle = false;
            byte[] y01 = new byte[keySize];
            SecureRandom.getInstanceStrong().nextBytes(y01);
            byte[] y02 = new byte[keySize];
            SecureRandom.getInstanceStrong().nextBytes(y02);
            Map<Boolean, byte[]> mapOfHashes = new HashMap<>();
            mapOfHashes.put(true, y01);
            mapOfHashes.put(false, y02);
            memory.put(0, mapOfHashes);
            int numberOfIterations = 0;
            boolean marker;
            operOne = memory.get(0).get(true);
            operTwo = memory.get(0).get(false);

            while (true) {
                Map<Boolean, byte[]> eternalMap = new HashMap<>();
                double start1 = System.currentTimeMillis();
                operOne = thread(eternalMap, operOne, true);
                double end1 = System.currentTimeMillis();
                if (endOfCycle) {
                    marker = true;
                    numberOfIterations = iter - numberOfComparing;
                    break;
                }
                double start2 = System.currentTimeMillis();
                operTwo = thread(eternalMap, operTwo, false);
                double end2 = System.currentTimeMillis();
                if (endOfCycle) {
                    marker = false;
                    numberOfIterations = iter - numberOfComparing;
                    break;
                }
                if (!eternalMap.isEmpty()) {
                    memory.put(iter, eternalMap);
                }
                iter++;
                totalTime += Math.max(end1 - start1, end2 - start2);
            }
            byte[] startValue = memory.get(0).get(marker);
            for (int j = 0; j < numberOfIterations; j++) {
                startValue = myHashFunc(startValue);
            }
            marker = !marker;
            Map<Boolean, byte[]> newMap = new HashMap<>();
            newMap.put(true, startValue);
            newMap.put(false, memory.get(0).get(marker));
            totalMemory += 2 * weightOfElement * memory.size();
            memory.clear();
            memory.put(0, newMap);
            endOfCycle = false;
            operOne = memory.get(0).get(true);
            operTwo = memory.get(0).get(false);
            double start = System.currentTimeMillis();
            while (true) {
                byte[] lastOperOne = operOne;
                byte[] lastOperTwo = operTwo;
                operOne = myHashFunc(operOne);
                operTwo = myHashFunc(operTwo);
                if (Arrays.equals(operOne, operTwo)) {
                    endOfCycle = true;
                    toHexString(lastOperOne);
                    toHexString(lastOperTwo);
                    toHexString(operTwo);
                    toHexString(operTwo);
                }
                if (endOfCycle) {
                    break;
                }
            }
                double end = System.currentTimeMillis();
                totalTime += end - start;
            System.out.println(totalTime);
            System.out.println(totalMemory);
            }
        }
    }
