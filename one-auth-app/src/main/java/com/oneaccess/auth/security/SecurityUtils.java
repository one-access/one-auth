package com.oneaccess.auth.security;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class SecurityUtils {

    public static PrivateKey loadPrivateKey(String pem) throws Exception {
        byte[] keyBytes = parseBase64Pem(pem);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        return KeyFactory.getInstance("RSA").generatePrivate(spec);
    }

    public static PublicKey loadPublicKey(String pem) throws Exception {
        byte[] keyBytes = parseBase64Pem(pem);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    public static byte[] parseBase64Pem(String pem) {
        // 1) Remove PEM header/footer
        String withoutHeaders = pem
                .replaceAll("-----BEGIN [^-]+-----", "")
                .replaceAll("-----END [^-]+-----", "");
        // 2) Remove all whitespace (newlines, spaces, tabs)
        String normalized = withoutHeaders.replaceAll("\\s+", "");
        // 3) Decode
        return Base64.getDecoder().decode(normalized);
    }
}
