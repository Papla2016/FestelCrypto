package org.example;
import java.io.*;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

public class Main {
    static int addedBytes = 0;
    //I|O methods

    public static byte[] reader(String name) throws Exception {
        InputStream fis = new FileInputStream(name);
        byte[] bytes = blockChecker(fis.readAllBytes());
        fis.close();
        return bytes;
    }
    public static void writer(byte[] write) throws Exception {
        writer(write,"out.txt");
    }
    public static void writer(byte[] write,String name) throws Exception{
        OutputStream out = new FileOutputStream(name);
        out.write(blockDeChecker(write));
        out.close();
    }

    public static short getCountableNum(long num){
        short k = 0;
        for (int i = 0;i <= 16;i++){
            k += (num & (1L << (64 - 2*i)))>0 ? (1<<(16 - i) ):0; //KAAAAAAAAAAAAAAAAAAAN Я ♥♥♥♥♥♥ битовые маски
        }
        return k;
    }
    public static byte[] shortToBytes(short x){
        ByteBuffer buffer = ByteBuffer.allocate(Short.BYTES);
        buffer.putShort(x);
        return buffer.array();
    }
    public static long bytesToLong(byte[] x){
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.put(x);
        buffer.flip();
        return buffer.getLong();
    }
    public static byte[] keyChanche(byte[] key, int i) {
        long k = bytesToLong(key);
        long j = (k << (i * 3)) + (k >> (64 - (i * 3)));
        return shortToBytes(getCountableNum(j));
    }

    public static byte[] byteXor(byte[] array_1, byte[] array_2){
        int i = 0;
        byte[] array_3 = new byte[array_1.length];
        for (byte j:array_1){
            array_3[i] =(byte) (j ^ array_2[i++]);
        }
        return array_3;
    }

    // Функция раунда Фейстеля F
    public static byte[] feistelRound(byte[] block1, byte[] block2) {
        if (block1.length != block2.length){
            throw new IllegalArgumentException("Block size");
        }
        byte[] result = new byte[block1.length];

        // Операция сдвига и XOR с инверсией
        for (int i = 0; i < block1.length; i++) {
            result[i] = (byte) ((block1[i] >>> 7) ^ (~block2[i]));
        }
        return result;
    }

    public static byte[] feistelEncrypt(byte[] blocks, byte[] key, int rounds,int blockLength) {
        byte[] X0 = Arrays.copyOfRange(blocks, 0, blockLength);
        byte[] X1 = Arrays.copyOfRange(blocks, blockLength, blockLength * 2);
        byte[] X2 = Arrays.copyOfRange(blocks, blockLength * 2, blockLength * 3);
        byte[] X3 = Arrays.copyOfRange(blocks, blockLength * 3, blockLength * 4);

        for (int i = 0; i < rounds; i++) {
            byte[] rangeKey = keyChanche(key,i);
            byte[] newX0 = byteXor(X2,rangeKey) ;
            byte[] newX1 = X0;
            byte[] newX2 = byteXor(byteXor(X3,feistelRound(X0,X1)),newX0);
            byte[] newX3 = X1;

            X0 = newX0;
            X1 = newX1;
            X2 = newX2;
            X3 = newX3;

        }

        return getBytes(blocks, blockLength, X0, X1, X2, X3);
    }
    public static byte[] feistelDecrypt(byte[] blocks, byte[] key, int rounds,int blockLength) {
        byte[] X0 = Arrays.copyOfRange(blocks, 0, blockLength);
        byte[] X1 = Arrays.copyOfRange(blocks, blockLength, blockLength * 2);
        byte[] X2 = Arrays.copyOfRange(blocks, blockLength * 2, blockLength * 3);
        byte[] X3 = Arrays.copyOfRange(blocks, blockLength * 3, blockLength * 4);

        for (int i = rounds - 1; i >= 0; i--) {
            byte[] roundKey = keyChanche(key,i);
            byte[] newX0 =  X1;
            byte[] newX1 = X3;
            byte[] newX2 = byteXor(X0,roundKey);
            byte[] newX3 = byteXor(byteXor(X2,X0),feistelRound(newX0,newX1));
            X0 = newX0;
            X1 = newX1;
            X2 = newX2;
            X3 = newX3;
        }

        return getBytes(blocks, blockLength, X0, X1, X2, X3);
    }

    private static byte[] getBytes(byte[] blocks, int blockLength, byte[] x0, byte[] x1, byte[] x2, byte[] x3) {
        byte[] result = new byte[blocks.length];
        System.arraycopy(x0, 0, result, 0, blockLength);
        System.arraycopy(x1, 0, result, blockLength, blockLength);
        System.arraycopy(x2, 0, result, blockLength * 2, blockLength);
        System.arraycopy(x3, 0, result, blockLength * 3, blockLength);

        return result;
    }

    public static byte[] blockChecker(byte[] mass){
        if (mass.length % 8 != 0){
            byte[] fixedMass = new byte[mass.length + ( 8- (mass.length% 8) )];
            new SecureRandom().nextBytes(fixedMass);
            System.arraycopy(mass,0,fixedMass,0,mass.length);
            addedBytes = 8- (mass.length% 8);
            return fixedMass;
        }
        return mass;
    }
    public static byte[] blockDeChecker(byte[] mass){
        if(addedBytes != 0){
            byte[] newMass = new byte[mass.length - addedBytes];
            System.arraycopy(mass,0,newMass,0,mass.length - addedBytes);
            return newMass;
        }
        return mass;
    }
    public static byte[] encryption(byte[] bytes,byte[] key,byte[] vectorInitialize){
        byte[] encrypted = new byte[bytes.length];
        for(int i = 0;i  < (bytes.length / 8);i++){
            byte[] j = feistelEncrypt(byteXor(Arrays.copyOfRange(bytes,i*8,8+i*8),vectorInitialize),key,10,2);
            System.arraycopy(j,0,encrypted,i*8,j.length);
            System.arraycopy(j,0,vectorInitialize,0,j.length);
        }
        return encrypted;
    }
    //decryption for cbc mode
    public static byte[] decryption(byte[] bytes, byte[] key,byte[] vectorInitialize){
        byte[] decrypted = new byte[bytes.length];
        for(int i = 0;i  < (bytes.length / 8);i++){
            byte[] temp = new byte[vectorInitialize.length];
            System.arraycopy(Arrays.copyOfRange(bytes,i*8,8+i*8),0,temp,0,temp.length);
            byte[] j = byteXor(feistelDecrypt(Arrays.copyOfRange(bytes,i*8,8+i*8),key,10,2),vectorInitialize);
            System.arraycopy(j,0,decrypted,i*8,j.length);
            System.arraycopy(temp,0,vectorInitialize,0,temp.length);
        }
        return decrypted;
    }

    public static void main(String[] args) throws Exception {
        byte[] key = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(key);
        byte[] vectorInitialize = new byte[8];
        random.nextBytes(vectorInitialize);
        byte[] data = reader("pom.xml");
        byte[] encrypted = encryption(data, key,Arrays.copyOf(vectorInitialize,8));
        System.out.println(Arrays.toString(encrypted));
        byte[] decrypted = decryption(encrypted, key,vectorInitialize);
        System.out.println(Arrays.toString(decrypted));
        System.out.println(Arrays.toString(data));
        writer(decrypted);
    }
}