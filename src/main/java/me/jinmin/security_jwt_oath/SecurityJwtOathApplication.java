package me.jinmin.security_jwt_oath;

import me.jinmin.security_jwt_oath.config.AppProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(AppProperties.class)
public class SecurityJwtOathApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecurityJwtOathApplication.class, args);
    }

}
