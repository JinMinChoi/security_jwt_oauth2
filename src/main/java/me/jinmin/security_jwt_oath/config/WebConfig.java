package me.jinmin.security_jwt_oath.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * CORS : Cross-Origin Resource Sharing
 * 동일한 출처가 아니어도 다른 출처에서의 자원을 요청하여 사용할 수 있도록 허용하는 구조
 * 오리진은 도메인과 비슷하지만, 프로토콜과 포트번호 포함 여부가 다르다.
 * - domain : naver.com
 * - origin : https://www.naver.com/PORT
 */
@Configuration
public class WebConfig implements WebMvcConfigurer {

    private final long MAX_AGE_SECS = 3600;

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry
                .addMapping("/**") //CORS 적용할 URL 패턴
                .allowedOrigins("*") //자원 공유 오리진 지정
                .allowedMethods("GET","POST","PUT","PATCH","DELETE","OPTIONS") //요청 허용 메서드
                .allowedHeaders("*") //요청 허용 헤더
                .allowCredentials(true) //요청 허용 쿠키
                .maxAge(MAX_AGE_SECS);
    }
}
