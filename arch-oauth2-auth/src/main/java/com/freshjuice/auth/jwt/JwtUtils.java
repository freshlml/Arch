package com.freshjuice.auth.jwt;

//import com.nimbusds.jose.*;
//import com.nimbusds.jose.crypto.RSASSASigner;
//import com.nimbusds.jose.crypto.RSASSAVerifier;
//import com.nimbusds.jose.jwk.RSAKey;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;

public class JwtUtils {
/*

    //JWS
    public static String token(String userId, String phone, RSAKey rsaKey) {
        JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).build();

        Map<String, Object> map = new HashMap<>();
        map.put("userId", userId);
        map.put("phone", phone);
        Payload payload = new Payload(map);

        JWSObject jwsObject = new JWSObject(jwsHeader, payload);

        try {
            JWSSigner jwsSigner = new RSASSASigner(rsaKey);
            jwsObject.sign(jwsSigner);
        } catch (JOSEException e) {
            e.printStackTrace();
        }
        return jwsObject.serialize();
    }

    public static void verify(String token, RSAKey rsaKey) {
        JWSObject jwsObject = null;
        try {
            jwsObject = JWSObject.parse(token);
        } catch (ParseException e) {
            e.printStackTrace();
        }
        RSAKey publicRsaKey = rsaKey.toPublicJWK();

        JWSVerifier jwsVerifier = null;
        try {
            jwsVerifier = new RSASSAVerifier(publicRsaKey);
            if (!jwsObject.verify(jwsVerifier)) {
                //"token签名不合法！"
            }
        } catch (JOSEException e) {
            e.printStackTrace();
        }

        Payload payload = jwsObject.getPayload();

    }
*/



}
