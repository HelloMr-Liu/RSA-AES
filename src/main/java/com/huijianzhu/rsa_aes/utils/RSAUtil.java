package com.huijianzhu.rsa_aes.utils;

import org.apache.tomcat.util.codec.binary.Base64;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKeyStructure;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import javax.crypto.Cipher;
import java.io.StringWriter;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

/**
 * 描述: RSA非对称加密
 * 非对称加密算法需要两个密钥：公开密钥（publickey）和私有密钥（privatekey）。公开密钥与私有密钥是一对，
 * 如果用公开密钥对数据进行加密，只有用对应的私有密钥才能解密；如果用私有密钥对数据进行加密，那么只有用对应的公开密钥才能解密。
 * 因为加密和解密使用的是两个不同的密钥，所以这种算法叫作非对称加密算法。简单的说是“公钥加密，私钥解密；私钥加密，公钥解密”。
 *
 * 优缺点：非对称加密算法的加密和解密用的密钥是不同的，这种加密方式是用数学上的难解问题构造的，通常加密解密的速度比较慢，
 *        适合偶尔发送数据的场合。优点是密钥传输方便。常见的非对称加密算法有：RSA算法、ECC算法和EIGamal算法。
 *
 * 范围：客户端传输重要信息给服务端，服务端返回的信息不需加密，例如绑定银行卡的时候，需要传递用户的银行卡号，手机号等重要信息，客户端这边就需要对这些重要信息进行加密，
 * 使用RSA公钥加密，服务端使用RSA解密，然后返回一些普通信息，比如状态码code,提示信息msg,提示操作是成功还是失败。这种场景下，仅仅使用RSA加密是可以的。
 *
 * RSA+AES加密过程
 * client：
 *  生成AES密钥，并用AES密钥对明文加密
 *  使用RSA公钥将AES密钥(aesKey)加密成encryptAesKey，作为HTTP请求头
 *  将AES加密明文后的密文（encryptData）作为请求体，将请求体和请求头一起发给sever
 *
 * sever：
 *  生成RSA密钥对（公钥、私钥）,提供接口给客户端，发送公钥
 *  获得AES加密后的请求头（encryptAesKey），获得加密后的请求体（encryptData）
 *  使用私钥解密请求头请求头（encryptAesKey）获得到AES密钥去请求体（encryptData）里的密文
 *
 *
 * @author 刘梓江
 * @Date 2020/12/24 13:25
 */
public class RSAUtil {

    public static final String KEY_ALGORITHM = "RSA";
    private static final String PUBLIC_KEY = "rsa_public_key";
    private static final String PRIVATE_KEY = "rsa_private_key";
    private static final String ENCODING = "UTF-8";

    /**
     * 加密
     * 用公钥加密
     * @param content
     * @param base64PublicKeyStr
     * @return
     * @throws Exception
     */
    public static String encryptByPublicKey(String content, String base64PublicKeyStr) throws Exception {
        byte[] inputBytes = content.getBytes(ENCODING);
        byte[] outputBytes = encryptByPublicKey(inputBytes, base64PublicKeyStr);
        return Base64.encodeBase64String(outputBytes);
    }

    /**
     * 加密
     * 用私钥加密
     * @param content
     * @param base64PrivateKeyStr
     * @return
     * @throws Exception
     */
    public static String encryptByPrivateKey(String content, String base64PrivateKeyStr) throws Exception {
        byte[] inputBytes = content.getBytes(ENCODING);
        byte[] outputBytes = encryptByPrivateKey(inputBytes, base64PrivateKeyStr);
        return Base64.encodeBase64String(outputBytes);
    }

    /**
     *
     * 解密
     * 用公钥解密
     * @param content
     * @param base64PublicKeyStr
     * @return
     * @throws Exception
     */
    public static String decryptByPublicKey(String content, String base64PublicKeyStr) throws Exception {
        byte[] inputBytes = Base64.decodeBase64(content);
        byte[] outputBytes = decryptByPublicKey(inputBytes, base64PublicKeyStr);
        return new String(outputBytes, ENCODING);
    }

    /**
     *
     * 解密
     * 用私钥解密
     * @param content
     * @param base64PrivateKeyStr
     * @return
     * @throws Exception
     */
    public static String decryptByPrivateKey(String content, String base64PrivateKeyStr) throws Exception {
        byte[] inputBytes = Base64.decodeBase64(content);
        byte[] outputBytes = decryptByPrivateKey(inputBytes, base64PrivateKeyStr);
        return new String(outputBytes, ENCODING);

    }

    /**
     *
     * 加密
     * 用公钥加密
     * @param content
     * @param base64PublicKeyStr
     * @return
     * @throws Exception
     */
    public static byte[] encryptByPublicKey(byte[] content, String base64PublicKeyStr) throws Exception {
        // 对公钥解密
        byte[] publicKeyBytes = Base64.decodeBase64(base64PublicKeyStr);

        // 取得公钥
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key publicKey = keyFactory.generatePublic(x509KeySpec);

        // 对数据加密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        return cipher.doFinal(content);

    }

    /**
     *
     * 加密
     * 用私钥加密
     * @param content
     * @param base64PrivateKeyStr
     * @return
     * @throws Exception
     */
    public static byte[] encryptByPrivateKey(byte[] content, String base64PrivateKeyStr) throws Exception {
        // 对密钥解密
        byte[] privateKeyBytes = Base64.decodeBase64(base64PrivateKeyStr);

        // 取得私钥
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key privateKey = keyFactory.generatePrivate(pkcs8KeySpec);

        // 对数据加密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);

        return cipher.doFinal(content);

    }

    /**
     *
     * 解密
     * 用公钥解密
     * @param content
     * @param base64PublicKeyStr
     * @return
     * @throws Exception
     */
    public static byte[] decryptByPublicKey(byte[] content, String base64PublicKeyStr) throws Exception {
        // 对密钥解密
        byte[] publicKeyBytes = Base64.decodeBase64(base64PublicKeyStr);

        // 取得公钥
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key publicKey = keyFactory.generatePublic(x509KeySpec);

        // 对数据解密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, publicKey);

        return cipher.doFinal(content);

    }

    /**
     * 解密
     * 用私钥解密
     * @param content
     * @param base64PrivateKeyStr
     * @return
     * @throws Exception
     */
    public static byte[] decryptByPrivateKey(byte[] content, String base64PrivateKeyStr) throws Exception {
        // 对密钥解密
        byte[] privateKeyBytes = Base64.decodeBase64(base64PrivateKeyStr);

        // 取得私钥  for PKCS#1
//        RSAPrivateKeyStructure asn1PrivKey = new RSAPrivateKeyStructure((ASN1Sequence) ASN1Sequence.fromByteArray(privateKeyBytes));
//        RSAPrivateKeySpec rsaPrivKeySpec = new RSAPrivateKeySpec(asn1PrivKey.getModulus(), asn1PrivKey.getPrivateExponent());
//        KeyFactory keyFactory= KeyFactory.getInstance("RSA");
//        PrivateKey priKey= keyFactory.generatePrivate(rsaPrivKeySpec);

        // 取得私钥  for PKCS#8
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key priKey = keyFactory.generatePrivate(pkcs8KeySpec);

        // 对数据解密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, priKey);
        return cipher.doFinal(content);
    }

    /**
     * 取得私钥
     * @param keyMap
     * @return
     * @throws Exception
     */
    public static String getBase64PrivateKeyStr(Map keyMap) throws Exception {
        Key key = (Key) keyMap.get(PRIVATE_KEY);
        return Base64.encodeBase64String(key.getEncoded());
    }

    /**
     * 取得公钥
     * @param keyMap
     * @return
     * @throws Exception
     */
    public static String getBase64PublicKeyStr(Map keyMap) throws Exception {
        Key key = (Key) keyMap.get(PUBLIC_KEY);
        return Base64.encodeBase64String(key.getEncoded());
    }


    /**
     * 将pkcs8格式的密匙抓换为pkcs1格式
     * @param privateKeyStr
     * @return
     */
    private static String pkcs8ToPkcs1(String privateKeyStr) throws Exception{
        byte[] privBytes = Base64.decodeBase64(privateKeyStr);
        PrivateKeyInfo pkInfo = PrivateKeyInfo.getInstance(privBytes);
        ASN1Encodable encodable = pkInfo.parsePrivateKey();
        ASN1Primitive primitive = encodable.toASN1Primitive();
        byte[] privateKeyPKCS1 = primitive.getEncoded();
        String type = "RSA PRIVATE KEY";
        PemObject pemObject = new PemObject(type, privateKeyPKCS1);
        StringWriter stringWriter = new StringWriter();
        PemWriter pemWriter = new PemWriter(stringWriter);
        pemWriter.writeObject(pemObject);
        pemWriter.close();
        String pemString = stringWriter.toString();
        String[] split = pemString.split("-----");
        String replace = split[2].replace("\r\n", "");
        return replace;
    }
    /**
     * 初始化密钥
     * @return
     * @throws Exception
     */
    public static Map<String,String> initKey() throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        keyPairGen.initialize(1024); // 初始化RSA1024安全些
        KeyPair keyPair = keyPairGen.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();        // 公钥
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();    // 私钥
        Map keyMap = new HashMap(2);
        keyMap.put(PUBLIC_KEY, publicKey);
        keyMap.put(PRIVATE_KEY, privateKey);
        return keyMap;
    }
}
