package com.freshjuice.monomer.common.utils;

import org.apache.shiro.codec.Base64;
import org.apache.shiro.crypto.AesCipherService;
import org.apache.shiro.crypto.SecureRandomNumberGenerator;
import org.apache.shiro.crypto.hash.DefaultHashService;
import org.apache.shiro.crypto.hash.HashRequest;
import org.apache.shiro.crypto.hash.Md5Hash;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.util.ByteSource;
import org.apache.shiro.util.SimpleByteSource;

import java.security.Key;

public class ShiroCrptyUtils {

    /*shiro  crpyt api 使用 */


    /**
     * shiro 中提供的 Base64编码/解码API (还不如用JDK8中实现),！以string为参数的api默认使用UTF-8编码
     */
    private static void shiroBase64Use() {
        String sourceText = "some bytes 世界";
        byte[] sourceByte = sourceText.getBytes(); //getBytes 默认使用-Dfile.encoding
        byte[] encodedByte = Base64.encode(sourceByte);
        String encodedText = new String(encodedByte); //默认使用-Dfile.encoding
        byte[] decodedByte = Base64.decode(encodedByte);
        String decodedText = new String(decodedByte);

        System.out.println("原始字符串: " + sourceText);
        System.out.println("encoded字符串: " + encodedText);
        System.out.println("decoded字符串: " + decodedText);

    }

    /**
     * shiro 中提供的散列算法 封装api
     */
    private static void shiroHashUse() {

        //1 MD5 hash and Sha256Hash 及其基类SimpleHash (源码来看，实际为基本的MessageDigest)
        //!如果使用string参数，内部toBytes对string默认使用UTF-8
        String sourceText = "some bytes 世界";
        byte[] sourceByte = sourceText.getBytes();
        byte[] saltByte = "salt 盐".getBytes();
        Md5Hash md5Hash = new Md5Hash(sourceByte, saltByte);  //构造时，已调用hash，进行了散列，通过getBytes返回散列之后的bytes
        byte[] md5HashedByte = md5Hash.getBytes(); //经过hash之后的bytes
        String md5HashedStringHex = md5Hash.toHex(); //经过hash之后的bytes十六进制值
        String md5HashedStringBase64Inner = md5Hash.toBase64(); //经过hash之后的bytes使用shiro的Base64(默认使用UTF-8)
        byte[] md5HashedStringBase64Byte = Base64.encode(md5Hash.getBytes());

        //2 HashService HashRequest (进一步的api封装)
        DefaultHashService hashService = new DefaultHashService(); //默认算法SHA-512
        hashService.setHashAlgorithmName("SHA-512");               //设置算法
        hashService.setPrivateSalt(new SimpleByteSource("私盐 salt".getBytes()));  //设置私盐，默认没有该值
        hashService.setGeneratePublicSalt(true);                  //如果不设置公盐，是否自动生成公盐(使用setRandomNumberGenerator设置的随机器生成公盐)，默认false
        hashService.setRandomNumberGenerator(new SecureRandomNumberGenerator()); //用于生成公盐
        hashService.setHashIterations(1);                          //生成Hash值的迭代次数

        HashRequest request = new HashRequest.Builder()
                .setAlgorithmName("MD5")                          //将覆盖HashService中的Algorithm
                .setSource(ByteSource.Util.bytes("hello 世界".getBytes()))
                .setSalt(ByteSource.Util.bytes("公盐 salt".getBytes()))  //设置公盐
                .setIterations(2)                                   //覆盖  service中生成Hash值的迭代次数
                .build();

        SimpleHash resultHash = (SimpleHash) hashService.computeHash(request); //使用SimpleHash对象封装hash之后的结果
        //resultHash.getBytes();
        //resultHash.toHex();
        //resultHash.toBase64();


    }

    /**
     * shiro 中对称加密/解密(Cipher)
     */
    private static void shiroCrpyUse() {
        //AesCipherService
        AesCipherService aesCipherService = new AesCipherService();
        aesCipherService.setKeySize(128);            //Aes 密钥长度
        Key key = aesCipherService.generateNewKey(); //生成aes 对称加密密钥 (KeyGenerator)
        String sourceText = "hello 世界";
        byte[] cipherByte = aesCipherService.encrypt(sourceText.getBytes(), key.getEncoded()).getBytes();
        String cipherText = new String(cipherByte);

        byte[] plainByte = aesCipherService.decrypt(cipherByte, key.getEncoded()).getBytes();
        String plainText = new String(plainByte);

        System.out.println("sourceText: " + sourceText);
        System.out.println("plainText: " + plainText);
        System.out.println("cipherText: " + cipherText);

    }

    public static void main(String argv[]) {



    }

}
