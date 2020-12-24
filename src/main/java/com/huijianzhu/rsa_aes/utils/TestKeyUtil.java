package com.huijianzhu.rsa_aes.utils;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;

/**
 * 描述: 通信加密钥匙类
 * @author 刘梓江
 * @Date 2020/12/24 10:50
 */
public class TestKeyUtil {

    public static void main(String[] args)throws Exception {
        Map<String, String> keys = RSAUtil.initKey();
        String base64PrivateKeyStr = RSAUtil.getBase64PrivateKeyStr(keys);
        String base64PublicKeyStr = RSAUtil.getBase64PublicKeyStr(keys);
        System.out.println(base64PrivateKeyStr);
        System.out.println(base64PublicKeyStr);

        String encrypt = RSAUtil.encryptByPublicKey("江西先锋软件职业技术学院", base64PublicKeyStr);
        String decrypt = RSAUtil.decryptByPrivateKey(encrypt, base64PrivateKeyStr);
        System.out.println("公匙加密:"+encrypt);
        System.out.println("私匙解密:"+decrypt);

        String privateKeyEncrypt = RSAUtil.encryptByPrivateKey("江西先锋软件职业技术学院TT", base64PrivateKeyStr);
        String publicKeyDecrypt = RSAUtil.decryptByPublicKey(privateKeyEncrypt, base64PublicKeyStr);
        System.out.println("私匙加密:"+privateKeyEncrypt);
        System.out.println("公匙解密:"+publicKeyDecrypt);

//        String origin = "刘梓江";
//        String encrypt = AESUtil.encrypt(origin, "MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAKg9bqVZB1hblPy7DduRb4fjnTqePy5au4oEBaAiu2PE/0fFCyt/qiUx4zav+a5CzVFTtFO3rWKoc0tyVV1odl0aEZaKn0TSeIVyp+emPlOvPH4pRQ8YU4hvCK2lawpT8ZzMeEVCto3AuwOVtM1jP8d/bIBsgFQM5jXZC4zu/+3LAgMBAAECgYEAmhpbRT19SuPoXm8ATIS1AmXtWQommVEmw07X0EzAFK0XoCfPCXMQ6Kz/kNI0A/jQlJP1c1Glkd72bL83ji3na/TNXadg539WUL9i4tjzrTpeLgW25yx5F9hl93nw3PxpKBOHe6QMnPMCexV7hJv3gE/bBkYMbVTaH2Po2Fo8AgECQQDsbuEOfYmqUNxW40q0osWSVYy3A/zbecvgucmye6bi3PlbgHWpVy71nugbfZseWwxaNW120Ca1n3MfVwrAuqVLAkEAtinMhMt/mxobhvaB0nCv8GIGRCaPIarRGJc8CZ748TzgYxfVJR7IrvMBXr2sfiyatBr+7cu6iMGAXn6G5IkJgQJAYHUH6jJ7JHniuqv2AWXats2iH9RHp360F5WUXPWnayx9qr/owNJpvRk8VmLTEvpQOslLREq9UCGiBOos394FqwJBAIRywdywJdj9U5R++YesHZCXhVzZ+GoPTDcoByQrrW+hxrjmJDj4OAxUbeOX36ph/h4EHuWBouA6aX7LWoMiTIECQQCzMWQv3ayJPI34vI1Q+Px0LBdQEmFQrwDnGa1PDl1dze4TliptllxEqeE9b5FK8qVkDLN9Ymo8lzow1h2103BW");
//        String decrypt = AESUtil.decrypt(encrypt, "MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAKg9bqVZB1hblPy7DduRb4fjnTqePy5au4oEBaAiu2PE/0fFCyt/qiUx4zav+a5CzVFTtFO3rWKoc0tyVV1odl0aEZaKn0TSeIVyp+emPlOvPH4pRQ8YU4hvCK2lawpT8ZzMeEVCto3AuwOVtM1jP8d/bIBsgFQM5jXZC4zu/+3LAgMBAAECgYEAmhpbRT19SuPoXm8ATIS1AmXtWQommVEmw07X0EzAFK0XoCfPCXMQ6Kz/kNI0A/jQlJP1c1Glkd72bL83ji3na/TNXadg539WUL9i4tjzrTpeLgW25yx5F9hl93nw3PxpKBOHe6QMnPMCexV7hJv3gE/bBkYMbVTaH2Po2Fo8AgECQQDsbuEOfYmqUNxW40q0osWSVYy3A/zbecvgucmye6bi3PlbgHWpVy71nugbfZseWwxaNW120Ca1n3MfVwrAuqVLAkEAtinMhMt/mxobhvaB0nCv8GIGRCaPIarRGJc8CZ748TzgYxfVJR7IrvMBXr2sfiyatBr+7cu6iMGAXn6G5IkJgQJAYHUH6jJ7JHniuqv2AWXats2iH9RHp360F5WUXPWnayx9qr/owNJpvRk8VmLTEvpQOslLREq9UCGiBOos394FqwJBAIRywdywJdj9U5R++YesHZCXhVzZ+GoPTDcoByQrrW+hxrjmJDj4OAxUbeOX36ph/h4EHuWBouA6aX7LWoMiTIECQQCzMWQv3ayJPI34vI1Q+Px0LBdQEmFQrwDnGa1PDl1dze4TliptllxEqeE9b5FK8qVkDLN9Ymo8lzow1h2103BW");
//        System.out.println(origin);
//        System.out.println(encrypt);
//        System.out.println(decrypt);

    }
}
