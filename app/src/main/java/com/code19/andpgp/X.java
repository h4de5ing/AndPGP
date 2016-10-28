package com.code19.andpgp;

import android.util.Base64;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.Cipher;

public class X {
    /* 密钥内容 base64 code======> 先urlenode的byte[] 再base64 得到硬编码的key
     * PUCLIC_KEY
     * PRIVATE_KEY
     *      L.e(Base64.encodeToString(URLEncoder.encode(PUCLIC_KEY, "UTF-8").getBytes(), Base64.DEFAULT));
     *      L.e(Base64.encodeToString(URLEncoder.encode(PRIVATE_KEY, "UTF-8").getBytes(), Base64.DEFAULT));
      *
      * */
    private static String PUCLIC_KEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCUBYSQwowxvWFHkevSAwLDoFt5\n" +
            "Kt60KyRATkD8jREzv2mDLLMFlxsDVms0km8SlIB8fyjFcONU0UwO8A9avDJEWQAz\n" +
            "ovpkWhaiO8zLuDTNMNiY7StAJzzt4rGw4m7AiGy08gGQvmtc31S3zQ6kg2XLhCM7\n" +
            "YdbxuTZQCs59szEUOQIDAQAB";
    private static String PRIVATE_KEY = "MIICXAIBAAKBgQCUBYSQwowxvWFHkevSAwLDoFt5Kt60KyRATkD8jREzv2mDLLMF\n" +
            "lxsDVms0km8SlIB8fyjFcONU0UwO8A9avDJEWQAzovpkWhaiO8zLuDTNMNiY7StA\n" +
            "Jzzt4rGw4m7AiGy08gGQvmtc31S3zQ6kg2XLhCM7YdbxuTZQCs59szEUOQIDAQAB\n" +
            "AoGADUMxTYcg6JP/U1pPttFuPfjwOTsOGTaEWP6p8/bvw6My4P3wTF/tm67yjBNS\n" +
            "wGdt27nI/WfP9pmKJwx7U7XpCvPLvEIo4AM3nuHN/H/vHFQiOx+Qoi82E236PAna\n" +
            "UXDMOtWlbKMJUTTlNFVHpURyNRao8GYq5efd1teRBjAI2AECQQDE+WXCC/bV4qd2\n" +
            "pDfL0qYOHaoOKwI5ntapukc4fYO1VtF5lUjxnpEGLs0SKwZh6UxibmCZJXSwSum0\n" +
            "ihWg80WpAkEAwGDJFmsxspsgBt1RDKl3NlMH5453IkVjFBkn6omCGD6JZ6uoY+iD\n" +
            "YZaEblWOQfH3a7uFuNrQnrqgsgAlD35UEQJACXPSb0p1sPPsh2QADXbxYxIHXCCy\n" +
            "PaOit4hp7IsRa/1blhMU6gtq+Dn8u1d3OfGhKcQUPKUwgVlG99P8j7m86QJBAI8x\n" +
            "O1wpi8NivdL+Nw7SsP5JjU+o9joXJalXFCP6GFCNc98roVpEPk6MJ6SsoAer4Dtb\n" +
            "SCyRCsmrJmN3wh4nLNECQEQ1HxwPikDlVnV6uPlCxc+aaRwkaT/eihYZnJSBJvOL\n" +
            "T45qkN3W7NxdOQP8/5gw9uTeH4Ggko9v5Tv81KOb9q0=\n";

    public static final String RSA = "RSA";// 非对称加密密钥算法
    public static final String ECB_PKCS1_PADDING = "RSA/ECB/PKCS1Padding";// 加密填充方式
    public static final int DEFAULT_KEY_SIZE = 1024;// 秘钥默认长度1024
    public static final byte[] DEFAULT_SPLIT = "#PART#".getBytes(); // 当要加密的内容超过bufferSize，则采用partSplit进行分块加密
    public static final int DEFAULT_BUFFERSIZE = (DEFAULT_KEY_SIZE / 8) - 11;// 117 当前秘钥支持加密的最大字节数
    public static final int DEFAULT_SIZE = (DEFAULT_KEY_SIZE / 8);//128 当前秘钥支持解密密的最大字节数
    private static byte[] pu_K;
    private static byte[] pr_K;
    private static RSAPublicKey sPublicKey;
    private static RSAPrivateKey sPrivateKey;

    public static void init() {
        try {
            KeyPair keyPair = RSAUtils.generateRSAKeyPair(X.DEFAULT_KEY_SIZE);
            // 公钥
            sPublicKey = (RSAPublicKey) keyPair.getPublic();
            //PublicKey publicKey = RSAUtils.loadPublicKey(PUCLIC_KEY);
            // 私钥
            sPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
            //PrivateKey privateKey = RSAUtils.loadPrivateKey(PRIVATE_KEY);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static byte[] getPuK() {
        try {
            //return pu_K == null ? pu_K = RSAUtils.loadPublicKey(URLDecoder.decode(URLDecoder.decode(new String(Base64.decode(PUCLIC_KEY, Base64.DEFAULT)), "UTF-8"), "UTF-8")).getEncoded() : pu_K;
            //return pu_K == null ? pu_K = RSAUtils.loadPublicKey(PUCLIC_KEY).getEncoded() : pu_K;
            return sPublicKey.getEncoded();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static byte[] getPrK() {
        try {
            //return pr_K == null ? pr_K = RSAUtils.loadPrivateKey(URLDecoder.decode(URLDecoder.decode(new String(Base64.decode(PRIVATE_KEY, Base64.DEFAULT)), "UTF-8"), "UTF-8")).getEncoded() : pr_K;
            //return pr_K == null ? pr_K = RSAUtils.loadPrivateKey(PRIVATE_KEY).getEncoded() : pr_K;
            return sPrivateKey.getEncoded();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String Base64_encodeToString(byte[] b) {
        return Base64.encodeToString(b, Base64.NO_WRAP);
    }

    public static byte[] Base64_decode(String b) {
        return Base64.decode(b, Base64.NO_WRAP);
    }

    /**
     * 公钥加密
     *
     * @param a
     * @return
     */
    public static String pu_en(String a) { // 公钥加密
        long start = System.currentTimeMillis();
        byte[] encryptBytes;
        try {
            encryptBytes = X.encryptByPublicKeyForSpilt(a.getBytes(), getPuK());
            long end = System.currentTimeMillis();
//            Log.e("x", "公钥加密耗时 cost time---->" + (end - start));
            String encryStr = Base64_encodeToString(encryptBytes);
//            Log.e("x", "加密后数据 --1-->" + encryStr);
//            Log.e("x", "加密后数据长度 --1-->" + encryStr.length());
            return encryStr;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }

    /**
     * 私钥解密
     *
     * @param a
     * @return
     */
    public static String pr_de(String a) {
        // 私钥解密
        long start = System.currentTimeMillis();
        byte[] decryptBytes;
        try {
            decryptBytes = X.decryptByPrivateKeyForSpilt(Base64_decode(a), getPrK());
            String decryStr = new String(decryptBytes);
            long end = System.currentTimeMillis();
//            Log.e("x", "私钥解密耗时 cost time---->" + (end - start));
//            Log.e("x", "解密后数据 --1-->" + decryStr);
            return decryStr;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }

//    public static String pr_en(String a) {
//        // 私钥加密
//        long start = System.currentTimeMillis();
//        byte[] encryptBytes;
//        try {
//            encryptBytes = X
//                    .encryptByPrivateKeyForSpilt(a.getBytes(), getPrK());
//            long end = System.currentTimeMillis();
//            Log.e("x", "私钥加密密耗时 cost time---->" + (end - start));
//            String encryStr = Base64_encodeToString(encryptBytes);
//            Log.e("x", "加密后json数据 --2-->" + encryStr);
//            Log.e("x", "加密后json数据长度 --2-->" + encryStr.length());
//            return encryStr;
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//        return "";
//    }
//
//    public static String pu_de(String a) {
//        // 公钥解密
//        long start = System.currentTimeMillis();
//        byte[] decryptBytes;
//        try {
//            decryptBytes = X.decryptByPublicKeyForSpilt(Base64_decode(a),
//                    getPuK());
//            String decryStr = new String(decryptBytes);
//            long end = System.currentTimeMillis();
//            Log.e("x", "公钥解密耗时 cost time---->" + (end - start));
//            Log.e("x", "解密后数据 --2-->" + decryStr);
//            return decryStr;
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//        return "";
//    }

    /**
     * 随机生成RSA密钥对
     *
     * @param keyLength 密钥长度，范围：512～2048 一般1024
     * @return
     */
    public static KeyPair generateRSAKeyPair(int keyLength) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(RSA);
            kpg.initialize(keyLength);
            return kpg.genKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 用公钥对字符串进行加密
     *
     * @param data 原文
     */
    public static byte[] encryptByPublicKey(byte[] data, byte[] publicKey)
            throws Exception {
        // 得到公钥
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);
        KeyFactory kf = KeyFactory.getInstance(RSA);
        PublicKey keyPublic = kf.generatePublic(keySpec);
        // 加密数据
        Cipher cp = Cipher.getInstance(ECB_PKCS1_PADDING);
        cp.init(Cipher.ENCRYPT_MODE, keyPublic);
        return cp.doFinal(data);
    }

    /**
     * 私钥加密
     *
     * @param data       待加密数据
     * @param privateKey 密钥
     * @return byte[] 加密数据
     */
    public static byte[] encryptByPrivateKey(byte[] data, byte[] privateKey)
            throws Exception {
        // 得到私钥
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey);
        KeyFactory kf = KeyFactory.getInstance(RSA);
        PrivateKey keyPrivate = kf.generatePrivate(keySpec);
        // 数据加密
        Cipher cipher = Cipher.getInstance(ECB_PKCS1_PADDING);
        cipher.init(Cipher.ENCRYPT_MODE, keyPrivate);
        return cipher.doFinal(data);
    }

    /**
     * 公钥解密
     *
     * @param data      待解密数据
     * @param publicKey 密钥
     * @return byte[] 解密数据
     */
    public static byte[] decryptByPublicKey(byte[] data, byte[] publicKey)
            throws Exception {
        // 得到公钥
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);
        KeyFactory kf = KeyFactory.getInstance(RSA);
        PublicKey keyPublic = kf.generatePublic(keySpec);
        // 数据解密
        Cipher cipher = Cipher.getInstance(ECB_PKCS1_PADDING);
        cipher.init(Cipher.DECRYPT_MODE, keyPublic);
        return cipher.doFinal(data);
    }

    /**
     * 使用私钥进行解密
     */
    public static byte[] decryptByPrivateKey(byte[] encrypted, byte[] privateKey)
            throws Exception {
        // 得到私钥
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey);
        KeyFactory kf = KeyFactory.getInstance(RSA);
        PrivateKey keyPrivate = kf.generatePrivate(keySpec);

        // 解密数据
        Cipher cp = Cipher.getInstance(ECB_PKCS1_PADDING);
        cp.init(Cipher.DECRYPT_MODE, keyPrivate);
        byte[] arr = cp.doFinal(encrypted);
        return arr;
    }

    /**
     * 用公钥对字符串进行分段加密
     */
    public static byte[] encryptByPublicKeyForSpilt(byte[] data, byte[] publicKey) throws Exception {
        int dataLen = data.length;
        if (dataLen <= DEFAULT_BUFFERSIZE) {
            return encryptByPublicKey(data, publicKey);
        }
        List<Byte> allBytes = new ArrayList<Byte>(2048);
        int bufIndex = 0;
        int subDataLoop = 0;
        byte[] buf = new byte[DEFAULT_BUFFERSIZE];
        for (int i = 0; i < dataLen; i++) {
            buf[bufIndex] = data[i];
            if (++bufIndex == DEFAULT_BUFFERSIZE || i == dataLen - 1) {
                subDataLoop++;
                if (subDataLoop != 1) {
                    for (byte b : DEFAULT_SPLIT) {
                        allBytes.add(b);
                    }
                }
                byte[] encryptBytes = encryptByPublicKey(buf, publicKey);
                for (byte b : encryptBytes) {
                    allBytes.add(b);
                }
                bufIndex = 0;
                if (i == dataLen - 1) {
                    buf = null;
                } else {
                    buf = new byte[Math
                            .min(DEFAULT_BUFFERSIZE, dataLen - i - 1)];
                }
            }
        }
        byte[] bytes = new byte[allBytes.size()];
        {
            int i = 0;
            for (Byte b : allBytes) {
                bytes[i++] = b.byteValue();
            }
        }
        return bytes;
    }

    /**
     * 分段加密
     *
     * @param data       要加密的原始数据
     * @param privateKey 秘钥
     */
    public static byte[] encryptByPrivateKeyForSpilt(byte[] data,
                                                     byte[] privateKey) throws Exception {
        int dataLen = data.length;
        if (dataLen <= DEFAULT_BUFFERSIZE) {
            return encryptByPrivateKey(data, privateKey);
        }
        List<Byte> allBytes = new ArrayList<Byte>(2048);
        int bufIndex = 0;
        int subDataLoop = 0;
        byte[] buf = new byte[DEFAULT_BUFFERSIZE];
        for (int i = 0; i < dataLen; i++) {
            buf[bufIndex] = data[i];
            if (++bufIndex == DEFAULT_BUFFERSIZE || i == dataLen - 1) {
                subDataLoop++;
                if (subDataLoop != 1) {
                    for (byte b : DEFAULT_SPLIT) {
                        allBytes.add(b);
                    }
                }
                byte[] encryptBytes = encryptByPrivateKey(buf, privateKey);
                for (byte b : encryptBytes) {
                    allBytes.add(b);
                }
                bufIndex = 0;
                if (i == dataLen - 1) {
                    buf = null;
                } else {
                    buf = new byte[Math
                            .min(DEFAULT_BUFFERSIZE, dataLen - i - 1)];
                }
            }
        }
        byte[] bytes = new byte[allBytes.size()];
        {
            int i = 0;
            for (Byte b : allBytes) {
                bytes[i++] = b.byteValue();
            }
        }
        return bytes;
    }

    /**
     * 公钥分段解密
     *
     * @param encrypted 待解密数据
     * @param publicKey 密钥
     */
    public static byte[] decryptByPublicKeyForSpilt(byte[] encrypted,
                                                    byte[] publicKey) throws Exception {
        int splitLen = DEFAULT_SPLIT.length;
        if (splitLen <= 0) {
            return decryptByPublicKey(encrypted, publicKey);
        }
        int dataLen = encrypted.length;
        List<Byte> allBytes = new ArrayList<Byte>(1024);
        int latestStartIndex = 0;
        for (int i = 0; i < dataLen; i++) {
            byte bt = encrypted[i];
            boolean isMatchSplit = false;
            if (i == dataLen - 1) {
                // 到data的最后了
                byte[] part = new byte[dataLen - latestStartIndex];
                System.arraycopy(encrypted, latestStartIndex, part, 0,
                        part.length);
                byte[] decryptPart = decryptByPublicKey(part, publicKey);
                for (byte b : decryptPart) {
                    allBytes.add(b);
                }
                latestStartIndex = i + splitLen;
                i = latestStartIndex - 1;
            } else if (bt == DEFAULT_SPLIT[0]) {
                // 这个是以split[0]开头
                if (splitLen > 1) {
                    if (i + splitLen < dataLen) {
                        // 没有超出data的范围
                        for (int j = 1; j < splitLen; j++) {
                            if (DEFAULT_SPLIT[j] != encrypted[i + j]) {
                                break;
                            }
                            if (j == splitLen - 1) {
                                // 验证到split的最后一位，都没有break，则表明已经确认是split段
                                isMatchSplit = true;
                            }
                        }
                    }
                } else {
                    // split只有一位，则已经匹配了
                    isMatchSplit = true;
                }
            }
            if (isMatchSplit) {
                byte[] part = new byte[i - latestStartIndex];
                System.arraycopy(encrypted, latestStartIndex, part, 0,
                        part.length);
                byte[] decryptPart = decryptByPublicKey(part, publicKey);
                for (byte b : decryptPart) {
                    allBytes.add(b);
                }
                latestStartIndex = i + splitLen;
                i = latestStartIndex - 1;
            }
        }
        byte[] bytes = new byte[allBytes.size()];
        {
            int i = 0;
            for (Byte b : allBytes) {
                bytes[i++] = b.byteValue();
            }
        }
        return bytes;
    }

    /**
     * 使用私钥分段解密
     */
    public static byte[] decryptByPrivateKeyForSpilt(byte[] encrypted,
                                                     byte[] privateKey) throws Exception {
        int splitLen = DEFAULT_SPLIT.length;
        if (splitLen <= 0) {
            return decryptByPrivateKey(encrypted, privateKey);
        }
        int dataLen = encrypted.length;
        List<Byte> allBytes = new ArrayList<Byte>(1024);
        int latestStartIndex = 0;
        for (int i = 0; i < dataLen; i++) {
            byte bt = encrypted[i];
            boolean isMatchSplit = false;
            if (i == dataLen - 1) {
                // 到data的最后了
                byte[] part = new byte[dataLen - latestStartIndex];
                System.arraycopy(encrypted, latestStartIndex, part, 0,
                        part.length);
                byte[] decryptPart = decryptByPrivateKey(part, privateKey);
                for (byte b : decryptPart) {
                    allBytes.add(b);
                }
                latestStartIndex = i + splitLen;
                i = latestStartIndex - 1;
            } else if (bt == DEFAULT_SPLIT[0]) {
                // 这个是以split[0]开头
                if (splitLen > 1) {
                    if (i + splitLen < dataLen) {
                        // 没有超出data的范围
                        for (int j = 1; j < splitLen; j++) {
                            if (DEFAULT_SPLIT[j] != encrypted[i + j]) {
                                break;
                            }
                            if (j == splitLen - 1) {
                                // 验证到split的最后一位，都没有break，则表明已经确认是split段
                                isMatchSplit = true;
                            }
                        }
                    }
                } else {
                    // split只有一位，则已经匹配了
                    isMatchSplit = true;
                }
            }
            if (isMatchSplit) {
                byte[] part = new byte[i - latestStartIndex];
                System.arraycopy(encrypted, latestStartIndex, part, 0,
                        part.length);
                byte[] decryptPart = decryptByPrivateKey(part, privateKey);
                for (byte b : decryptPart) {
                    allBytes.add(b);
                }
                latestStartIndex = i + splitLen;
                i = latestStartIndex - 1;
            }
        }
        byte[] bytes = new byte[allBytes.size()];
        {
            int i = 0;
            for (Byte b : allBytes) {
                bytes[i++] = b.byteValue();
            }
        }
        return bytes;
    }
}
