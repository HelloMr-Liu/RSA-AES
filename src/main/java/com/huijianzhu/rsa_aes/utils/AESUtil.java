package com.huijianzhu.rsa_aes.utils;

import org.springframework.util.Base64Utils;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

/**
 * 描述: AES 对称加密 用来替代原先的DES加密算法。
 *
 * 优缺点：对称加密算法是应用较早的加密算法，技术成熟。加密和解密用到的密钥是相同的，这种加密方式加密速度非常快，
 *        适合经常发送数据的场合。缺点是密钥的传输比较麻烦。常见的对称加密算法有：AES算法，DES算法，3DES算法等等。
 *
 * 提示：实际中，一般是通过RSA加密AES的密钥，传输到接收方，接收方解密得到AES密钥，然后发送方和接收方用AES密钥来通信。
 *
 * @author 刘梓江
 * @Date 2020/12/24 11:48
 */
public class AESUtil {

    private static final String KEY_ALGORITHM = "AES";
    private static final String DEFAULT_CIPHER_ALGORITHM = "AES/ECB/PKCS5Padding";//默认的加密算法
//    //自定义密码
//    private static final String ASSETS_DEV_PWD_FIELD = "xxxx";
//
//    public static String getAssetsDevPwdField() {
//        return ASSETS_DEV_PWD_FIELD;
//    }

    /**
     * AES 加密操作
     * @param content  待加密内容
     * @param password 加密密码
     * @return 返回Base64转码后的加密数据
     */
    public static String encrypt(String content, String password) throws Exception {
        Cipher cipher = Cipher.getInstance(DEFAULT_CIPHER_ALGORITHM);   // 创建密码器
        byte[] byteContent = content.getBytes("UTF-8");
        cipher.init(Cipher.ENCRYPT_MODE, getSecretKey(password));       // 初始化为加密模式的密码器
        byte[] result = cipher.doFinal(byteContent);                    // 加密
        return Base64Utils.encodeToString(result);                      //通过Base64转码返回
    }

    /**
     * AES 解密操作
     * @param content  待解密内容
     * @param password 解密密码
     * @return 返回Base64转码后的解密数据
     */
    public static String decrypt(String content, String password) throws Exception  {
        Cipher cipher = Cipher.getInstance(DEFAULT_CIPHER_ALGORITHM);          //实例化
        cipher.init(Cipher.DECRYPT_MODE, getSecretKey(password));              //使用密钥初始化，设置为解密模式
        byte[] result = cipher.doFinal(Base64Utils.decodeFromString(content)); //执行操作
        return  new String(result, "UTF-8");
    }

    /**
     * 生成加密秘钥
     * @return
     */
    private static SecretKeySpec getSecretKey(String password) throws Exception {
        //返回生成指定算法密钥生成器的 KeyGenerator 对象
        KeyGenerator kg = kg = KeyGenerator.getInstance(KEY_ALGORITHM);
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        random.setSeed(password.getBytes());
        kg.init(128, random);//AES 要求密钥长度为 128
        SecretKey secretKey = kg.generateKey();//生成一个密钥
        return new SecretKeySpec(secretKey.getEncoded(), KEY_ALGORITHM);// 转换为AES专用密钥
    }

//    public static void main(String[] args) throws Exception {
//        String origin = "刘梓江";
//        String encrypt = AESUtil.encrypt(origin, AESUtil.ASSETS_DEV_PWD_FIELD);
//        String decrypt = AESUtil.decrypt(encrypt, AESUtil.ASSETS_DEV_PWD_FIELD);
//        System.out.println(origin);
//        System.out.println(encrypt);
//        System.out.println(decrypt);
//    }
}
