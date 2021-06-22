package me.jinmin.security_jwt_oath.security;

import io.jsonwebtoken.*;
import me.jinmin.security_jwt_oath.config.AppProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.util.Date;

/**
 * 유요한 JWT 토큰 생성
 */
@Service
public class TokenProvider {
    private static final Logger logger = LoggerFactory.getLogger(TokenProvider.class);

    private AppProperties appProperties;

    public TokenProvider(AppProperties appProperties) {
        this.appProperties = appProperties;
    }

    public String createToken(Authentication authentication) {
        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();

        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + appProperties.getAuth().getTokenExpirationMsec());

        return Jwts.builder()
                .setSubject(Long.toString(userPrincipal.getId()))
                .setIssuedAt(new Date())
                .setExpiration(expiryDate)
                .signWith(SignatureAlgorithm.HS512, appProperties.getAuth().getTokenSecret())
                .compact();
    }

    public Long getUserIdFromToken(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(appProperties.getAuth().getTokenSecret())
                .parseClaimsJws(token)
                .getBody();

        return Long.parseLong(claims.getSubject());
    }

    public boolean validateToken(String authToken) {
        try {
            Jwts.parser().setSigningKey(appProperties.getAuth().getTokenSecret()).parseClaimsJws(authToken);
            return true;
        } catch (SignatureException e) {
            logger.error("유효하지 않은 JWT 서명");
        } catch (MalformedJwtException e) {
            logger.error("유효하지 않은 JWT 토큰");
        } catch (ExpiredJwtException e) {
            logger.error("만료된 JWT 토큰");
        } catch (UnsupportedJwtException e) {
            logger.error("지원하지 않는 JWT");
        } catch (IllegalArgumentException e) {
            logger.error("비어있는 JWT");
        }

        return false;
    }
}
