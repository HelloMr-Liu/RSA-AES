package com.huijianzhu.rsa_aes.definition;

/**
 * 描述: 定义封装请求头加密内容对应后的解密信息属性 请求头解密后的内容有  token、和AES密匙(用来加解密)
 * @author 刘梓江
 * @Date 2020/12/24 14:10
 */
public class RequestHeadCipherDefinition {
    /**
     * 权限验证token
     */
    private String AuthenticationToken;

    /**
     * AES密钥(aesKey)
     */
    private String encryptAesKey;

    public String getAuthenticationToken() {
        return AuthenticationToken;
    }

    public void setAuthenticationToken(String authenticationToken) {
        AuthenticationToken = authenticationToken;
    }

    public String getEncryptAesKey() {
        return encryptAesKey;
    }

    public void setEncryptAesKey(String encryptAesKey) {
        this.encryptAesKey = encryptAesKey;
    }
}
