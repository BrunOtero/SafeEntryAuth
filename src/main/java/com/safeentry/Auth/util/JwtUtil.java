package com.safeentry.Auth.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import java.util.Base64;

@Component
public class JwtUtil {

    // A chave secreta será lida do application.properties
    @Value("${jwt.secret}")
    private String secret;

    // Tempo de expiração do token em milissegundos, lido do application.properties
    @Value("${jwt.expiration}")
    private long expiration;

    // Chave secreta decodificada para uso com JJWT
    private SecretKey getSigningKey() {
        // Decodifica a chave secreta Base64 para ser usada pelo JJWT
        byte[] keyBytes = Base64.getDecoder().decode(secret);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    // Extrai o nome de usuário (email) do token
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    // Extrai a data de expiração do token
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    // Extrai um "claim" específico do token
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // Extrai todos os "claims" (payload) do token
    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder().setSigningKey(getSigningKey()).build().parseClaimsJws(token).getBody();
    }

    // Verifica se o token expirou
    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    // Gera o token para um determinado usuário (email) e tipo de usuário
    public String generateToken(String email, String userType) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("type", userType); // Adiciona o tipo de usuário como um claim
        return createToken(claims, email);
    }

    // Cria o token JWT
    private String createToken(Map<String, Object> claims, String subject) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject) // O subject geralmente é o identificador único (email neste caso)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSigningKey(), SignatureAlgorithm.HS512)
                .compact();
    }

    // Valida o token
    public Boolean validateToken(String token, String username) {
        final String extractedUsername = extractUsername(token);
        return (extractedUsername.equals(username) && !isTokenExpired(token));
    }
}