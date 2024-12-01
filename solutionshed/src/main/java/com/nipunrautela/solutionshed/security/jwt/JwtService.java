package com.nipunrautela.solutionshed.security.jwt;

import com.nipunrautela.solutionshed.user.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Date;
import java.util.function.Function;

@Service
public class JwtService {
    private final String secretKey;

    @Value("${security.jwt.issuer}")
    private String issuer;

    @Value("${security.jwt.expiration-time}")
    private long expirationTime;

    @Autowired
    public JwtService() throws NoSuchAlgorithmException {
        SecretKey generatedSecretKey = KeyGenerator.getInstance("HmacSHA256").generateKey();
        this.secretKey = Base64.getEncoder().encodeToString(generatedSecretKey.getEncoded());
    }

    public String generateJwt(String subject, Claims addtionalClaims) {
        return Jwts.builder()
                .claims(addtionalClaims)
                .subject(subject)
                .issuer(this.issuer)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + this.expirationTime))
                .signWith(getSigningKey())
                .compact();
    }

    public JwtData getJwtData(String token) {
        String subject = getSubject(token);
        String issuer = extractExtraClaim(token, "issuer", String.class);
        Date issuedDate = extractPrimaryClaim(token, Claims::getIssuedAt);
        Date expDate = getExpiration(token);
        Claims extraClaims = extractAllClaims(token);

        return new JwtData(
                subject, issuer, extraClaims, expDate, issuedDate
        );
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private boolean isJwtSigned(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .isSigned(token);
    }

    private <T> T extractPrimaryClaim(String token, Function<Claims, T> claimResolver) {
        final Claims claims = extractAllClaims(token);
        return claimResolver.apply(claims);
    }

    private <T> T extractExtraClaim(String token, String claimName, Class<T> claimClass) {
        final Claims claims = extractAllClaims(token);
        return claims.get(claimName, claimClass);
    }

    private Date getExpiration(String token) {
        return extractPrimaryClaim(token, Claims::getExpiration);
    }

    public boolean isTokenExpired(String token) {
        return getExpiration(token).before(new Date(System.currentTimeMillis()));
    }

    private String getSubject(String token) {
        return extractPrimaryClaim(token, Claims::getSubject);
    }

    public boolean isTokenValid(String token) {
        return (!isTokenExpired(token) && isJwtSigned(token));
    }

    private SecretKey getSigningKey() {
        byte[] secretKeyBytes = Base64.getDecoder().decode(this.secretKey.getBytes());
        return new SecretKeySpec(secretKeyBytes, 0, secretKeyBytes.length, "HmacSHA256");
    }
}
