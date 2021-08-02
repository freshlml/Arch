package com.freshjuice.auth.jwt;

public class FlJwtSample {

    /**
     * JWT: Json Web Token
     * JWS: Json Web Signature, 实现JWT，Header;PayLoad;Signature,@see xy-common
     * JWK: Json Web Encryption, 实现JWT
     *      1 JOSE含义与JWS头部相同。
     *      2 生成一个随机的Content Encryption Key （CEK）。
     *      3 使用RSAES-OAEP 加密算法，用公钥加密CEK，生成JWE Encrypted Key。
     *      4 生成JWE初始化向量。
     *      5 使用AES GCM加密算法对明文部分进行加密生成密文Ciphertext,算法会随之生成一个128位的认证标记Authentication Tag。
     *      6 对五个部分分别进行base64编码。
     *
     */

    /**
     * nimbus-jose-jwt: JWT开源库
     *
     *
     *
     */






}
