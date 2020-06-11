/*

.. To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package advancedencryptionstandard;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Random;

/**
 *
 * @author padom
 */
public class AdvancedEncryptionStandard {
    static final private int rowSize=4;
    
    static private final int Sbox[] =
    {
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F,0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE,0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
    };
    static private final int [] invSbox= {
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
        0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
        0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
        0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
        0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
        0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
        0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
        0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
        0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
        0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
        0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
        0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
        0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
        0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
        0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
    };
    public static final int[] rcon = 
        {0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
        0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
        0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
        0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
        0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
        0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
        0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
        0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
        0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
        0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
        0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
        0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
        0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
        0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
        0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
        0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb,0x8d};
    
    private byte[][] roundKeys = new byte[11][16];
    private byte [] passwordBytes;
    private byte[][] textBytes;
    public int byteToint(byte arr)
    { 
        return arr&0xff;
    }
    public byte[] StringToByte(String str){
        byte [] buffer = new byte[str.length()*2];
        for(int i=0;i<buffer.length;i+=2){
            buffer[i]=(byte)(str.charAt(i/2)>>8);
            buffer[i+1]=(byte)str.charAt(i/2);

        }
        return buffer;
    }
    public String byteToString(byte []arr)
    { 
        StringBuffer sb = new StringBuffer();
        for(int i=0;i<arr.length;i+=2){
            sb.append((char) (byteToint(arr[i])<<8 ^ byteToint(arr[i+1])));
        }
        return sb.toString();
    }   
    public boolean setPassword(String password){
        if(password.length()!=16){
            System.out.print("password pass is 16 lengh");
            return false;
        }
        passwordBytes= password.getBytes();
        keySchedule();
        return true;
    }
    public void setText(String plainText) throws UnsupportedEncodingException{
        byte[] b = StringToByte(plainText);
        //plainText over 16
        if(b.length%16!=0){
            this.textBytes=new byte[b.length/16+1][16];
            if(b.length<16){
                for(int i=0;i<b.length;i++){
                    this.textBytes[0][i]=b[i];
                }
                for(int i=b.length;i<16;i++){
                    this.textBytes[0][i]=(byte)0xff;
                }
            }
            else{
                for(int i=0;i<b.length/16;i++){
                    for(int j=0;j<16;j++){
                       this.textBytes[i][j]=b[(i*16)+j];
                    }
                }
                for(int i=0;i<b.length%16;i++){
                    this.textBytes[b.length/16][i]=b[((b.length/16)*16)+i];
                }
                for(int i=b.length%16;i<16;i++){
                    this.textBytes[b.length/16][i]=(byte)0xff;
                }
            }
        }
        else{
            this.textBytes=new byte[b.length/16][16];
            for(int i=0;i<b.length/16;i++){
                for(int j=0;j<16;j++){
                    this.textBytes[i][j]=b[j+(i*16)];
                }
            }
        }
    }
    public void subBytes(byte [] arr){
        for(int i=0;i<arr.length;i++){
            arr[i]=(byte) Sbox[byteToint(arr[i])];
        }
    }
    public void invSubBytes(byte[] arr){
        for(int i=0;i<arr.length;i++){
            arr[i]=(byte) invSbox[byteToint(arr[i])];
        }
    }
    public void shiftRows(byte[] arr) {
        for (int i = rowSize; i < arr.length; i+=rowSize) {
            arr=leftRotate(arr, i,i/rowSize);
        }
    }
    private byte[] leftRotate(byte[] arr, int locate,int times)
    {
        while(times>0){
            byte temp=arr[locate];
            for(int i=locate;i<locate+rowSize-1;i++){
                arr[i]=arr[i+1];
            }

            arr[locate+rowSize-1]=temp;
            times--;
        }
        return arr;
    }
    public void invShiftRows(byte[] arr) {
        for (int i = rowSize; i < arr.length; i+=rowSize) {
            arr=rightRotate(arr, i,i/4);
        }
    }
    private byte[]rightRotate(byte[] arr, int locate,int times)
    {
        while(times>0){
            byte temp=arr[locate+rowSize-1];
            for(int i=locate+rowSize-1;i>locate;i--){
                arr[i]=arr[i-1];
            }
            arr[locate]=temp;
            times--;
        }
        return arr;
    }
    private static int slowMult(byte a, byte b) {
        int aa = a, bb = b, r = 0, t;
        while (aa != 0) {
            if ((aa & 1) != 0)
                r = (r ^ bb);
            t = (bb & 0x80);
            bb = (bb << 1);
            if (t != 0)
                bb = (bb ^ 0x1b);
            aa = ((aa & 0xff) >> 1);
        }
        return r;
    }
    private void mixColumns(byte [] arr) {
        byte [] temp= new byte [arr.length];
        System.arraycopy(arr, 0, temp, 0, temp.length);
        for(int i=0;i<4;i++){
            arr[i] =            (byte) (slowMult(temp[i],(byte)2) ^ slowMult(temp[i+rowSize], (byte)3) ^ slowMult(temp[i+rowSize*2], (byte)1) ^ slowMult(temp[i+rowSize*3], (byte)1));
            arr[i+rowSize] =    (byte) (slowMult(temp[i], (byte)1) ^ slowMult(temp[i+rowSize], (byte)2) ^ slowMult(temp[i+rowSize*2],(byte)3) ^ slowMult(arr[i+rowSize*3],  (byte)1));
            arr[i+rowSize*2] =  (byte) (slowMult(temp[i], (byte)1) ^ slowMult(temp[i+rowSize], (byte)1) ^ slowMult(temp[i+rowSize*2],(byte)2) ^ slowMult(temp[i+rowSize*3], (byte)3));
            arr[i+rowSize*3] =  (byte) (slowMult(temp[i], (byte)3) ^ slowMult(temp[i+rowSize], (byte)1) ^ slowMult(temp[i+rowSize*2],(byte)1) ^ slowMult(temp[i+rowSize*3], (byte)2));
        }
    }
    private void invMixColumns(byte[] arr) {
        byte [] temp= new byte [arr.length];
        System.arraycopy(arr, 0, temp, 0, temp.length);
        for(int i=0;i<4;i++){
            arr[i] =            (byte) (slowMult(temp[i], (byte)14) ^ slowMult(temp[i+rowSize], (byte)11) ^ slowMult(temp[i+rowSize*2], (byte)13) ^ slowMult(temp[i+rowSize*3], (byte)9));
            arr[i+rowSize] =    (byte) (slowMult(temp[i], (byte)9) ^ slowMult(temp[i+rowSize],  (byte)14) ^ slowMult(temp[i+rowSize*2], (byte)11) ^ slowMult(temp[i+rowSize*3], (byte)13));
            arr[i+rowSize*2] =  (byte) (slowMult(temp[i], (byte)13) ^ slowMult(temp[i+rowSize], (byte)9) ^ slowMult(temp[i+rowSize*2],  (byte)14) ^ slowMult(temp[i+rowSize*3], (byte)11));
            arr[i+rowSize*3] =  (byte) (slowMult(temp[i], (byte)11) ^ slowMult(temp[i+rowSize], (byte)13) ^ slowMult(temp[i+rowSize*2], (byte)9) ^ slowMult(temp[i+rowSize*3],  (byte)14));
        }
    }
    public void addRoundKey(byte[] bytematrix, byte[] keymatrix)
    {
        for (int i = 0; i < bytematrix.length; i++) {
                bytematrix[i] ^= keymatrix[i];
        }
    }
    public void keyScheduleCore(int round){
        //roate
        byte temp=roundKeys[round-1][3];
        for(int i=0;i<rowSize*3;i+=rowSize){
            roundKeys[round][i]=roundKeys[round-1][3+i+rowSize];
        }
        roundKeys[round][rowSize*3]=temp;
        
        for(int i=0;i<rowSize*4;i+=rowSize){
            roundKeys[round][i]=(byte) Sbox[byteToint(roundKeys[(byte)round][i])];
        }        
        
        roundKeys[round][0]=        (byte) (roundKeys[round-1][0]^roundKeys[round][0]^rcon[round]);
        roundKeys[round][rowSize]=  (byte) (roundKeys[round-1][rowSize]^roundKeys[round][rowSize]);
        roundKeys[round][rowSize*2]=(byte) (roundKeys[round-1][rowSize*2]^roundKeys[round][rowSize*2]);
        roundKeys[round][rowSize*3]=(byte) (roundKeys[round-1][rowSize*3]^roundKeys[round][rowSize*3]);

    }
    public void keySchedule()
    {
        System.arraycopy(passwordBytes, 0, roundKeys[0], 0, roundKeys[0].length);
        
        for(int k=1;k<11;k++){
            keyScheduleCore(k);
            for(int i=1;i<4;i++){
                roundKeys[k][i]=          (byte) (roundKeys[k-1][i]^roundKeys[k][i-1]);
                roundKeys[k][i+rowSize]=  (byte) (roundKeys[k-1][i+rowSize]^roundKeys[k][i-1+rowSize]);
                roundKeys[k][i+rowSize*2]=(byte) (roundKeys[k-1][i+rowSize*2]^roundKeys[k][i-1+rowSize*2]);
                roundKeys[k][i+rowSize*3]=(byte) (roundKeys[k-1][i+rowSize*3]^roundKeys[k][i-1+rowSize*3]);
            }
        }
    }
    
    public byte[] encrypt128(byte [] arr){
        addRoundKey(arr, roundKeys[0]);
        for(int i=1;i<10;i++){
            subBytes(arr);
            shiftRows(arr);
            mixColumns(arr);
            addRoundKey(arr, roundKeys[i]);
        }
        subBytes(arr);
        shiftRows(arr);
        addRoundKey(arr, roundKeys[10]);
        
        return arr;
    }
    public byte[] decrypt128(byte [] arr){
        addRoundKey(arr, roundKeys[10]);
        invShiftRows(arr);
        invSubBytes(arr);
        for(int i=9;i>0;i--){
            addRoundKey(arr, roundKeys[i]);
            invMixColumns(arr);
            invShiftRows(arr);
            invSubBytes(arr);
        }
        addRoundKey(arr, roundKeys[0]);
        
        return arr;
    }
    public String encrypt() throws UnsupportedEncodingException{
//         StringBuffer buffer= new StringBuffer();
         byte[] buffer = new byte[textBytes.length*16];
        
        byte [] beforeCypher=new byte[16];
        for(int i=0;i<16;i++){
            beforeCypher[i]=(byte) i;
        }
        
        for(int i=0;i<textBytes.length;i++){
            addRoundKey(textBytes[i], beforeCypher);
            encrypt128(textBytes[i]);
//            buffer.append(new String(textBytes[i]));
            System.arraycopy(textBytes[i], 0, buffer, i*16, 16);
            beforeCypher=textBytes[i];
        }

        return byteToString(buffer);
    } 
    public String decrypt() throws UnsupportedEncodingException{  
        byte [] beforeCypher=new byte[16];
        for(int i=0;i<16;i++){
            beforeCypher[i]=(byte) i;
        }
        byte [] currentCypher= new byte[16];

        //ECB block mode decryt code 
        for(int i=0;i<textBytes.length;i++){
            System.arraycopy(textBytes[i], 0, currentCypher, 0, 16);
            decrypt128(textBytes[i]);
            addRoundKey(textBytes[i], beforeCypher);
            //erase padding
            System.arraycopy(currentCypher, 0, beforeCypher, 0, 16);
        }
        
        //calculate padd size
        int paddSize=0;
        if(textBytes[textBytes.length-1][14]==(byte)0xff  && textBytes[textBytes.length-1][15]==(byte)0xff){
            for(int k=0;k<16;k+=2){
                if(textBytes[textBytes.length-1][k]==(byte)0xff && textBytes[textBytes.length-1][k+1]==(byte)0xff) {
                    paddSize=16-k;
                    break;
                }
            }
        }
        //copy textBytes to buffer, except padding
        byte [] buffer = new byte[textBytes.length*16-paddSize];
        for(int i=0;i<textBytes.length;i++){
                    if(i==textBytes.length-1)
                System.arraycopy(textBytes[i], 0, buffer,i*16, textBytes[i].length-paddSize);
            else
                System.arraycopy(textBytes[i], 0, buffer,i*16, textBytes[i].length);             
        }

        //buffer change String
        return byteToString(buffer);
    }

//    @SuppressWarnings("empty-statement")
//    public static void main(String[] args) throws UnsupportedEncodingException {
//        // TODO code application logic hereaa
//
//        AdvancedEncryptionStandard aes = new AdvancedEncryptionStandard();
//        aes.setPassword("This is password");
//        aes.setText("쁌爕ᬰ풿嶾훳譨쯜⻖뱏销嚛璒踰ﲱ");
////        aes.setText("쾧ἑᛤ㎬毰궘흮㧈쭃ﲒ퀚巁掯ⓐ⿻១඀⽿๢♄");     
////       System.out.println(aes.encrypt());        
//        System.out.println(aes.decrypt());
//    }
}

