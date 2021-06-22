package me.jinmin.security_jwt_oath.config;

import lombok.RequiredArgsConstructor;
import me.jinmin.security_jwt_oath.domain.Role;
import me.jinmin.security_jwt_oath.security.CustomUserDetailsService;
import me.jinmin.security_jwt_oath.security.TokenAuthenticationFilter;
import me.jinmin.security_jwt_oath.security.oauth2.CustomOAuth2UserService;
import me.jinmin.security_jwt_oath.security.oauth2.HttpCookieOAuth2AuthorizationRequestRepository;
import me.jinmin.security_jwt_oath.security.oauth2.OAuth2AuthenticationFailureHandler;
import me.jinmin.security_jwt_oath.security.oauth2.OAuth2AuthenticationSuccessHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * override된 configure(HttpSecurity http)의 antMachers를 이용해 ROLE을 확인
 */
@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
@EnableGlobalMethodSecurity(
        securedEnabled = true,
        jsr250Enabled = true,
        prePostEnabled = true
)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CustomUserDetailsService customUserDetailsService;
    private final CustomOAuth2UserService customOAuth2UserService;
    private final OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;
    private final OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler;
    private final HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository;

    @Bean
    public TokenAuthenticationFilter tokenAuthenticationFilter() {
        return new TokenAuthenticationFilter();
    }

    /**
     * JWT를 사용하면 Session에 저장하지 않고 Authorization Request를 Based64 encoded cookie에 저장
     */
    @Bean
    public HttpCookieOAuth2AuthorizationRequestRepository cookieAuthorizationRequestRepository(){
        return new HttpCookieOAuth2AuthorizationRequestRepository();
    }

    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    /**
     * Authrization에 사용할 userDetailsService와 PasswordEncode 정의
     */
    @Override
    protected void configure(AuthenticationManagerBuilder builder) throws Exception {
        builder
                .userDetailsService(customUserDetailsService)
                .passwordEncoder(passwordEncoder());
    }

    /**
     * AhthenticationManager를 외부에서 사용하기 위해 @Bean 설정으로
     * Spring Security 밖으로 추출
     */
    @Bean(BeanIds.AUTHENTICATION_MANAGER)
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .cors() //cors 허용
                .and()
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) //Session 비활성화
                .and()
                    .csrf().disable() //csrf 비활성화
                    .formLogin().disable() //로그인폼 비활성화
                    .httpBasic().disable() //기본 로그인 창 비활성화
                    .authorizeRequests()
                        .antMatchers("/").permitAll()
                        .antMatchers("/api/**").hasAnyRole(Role.GUEST.name(), Role.USER.name(), Role.ADMIN.name())
                        .antMatchers("/auth/**", "oauth2/**").permitAll()
                        .anyRequest().authenticated()
                .and()
                    .oauth2Login()
                        .authorizationEndpoint()
                        .baseUri("/oauth2/authorization") //클라이언트 첫 로그인 URI
                        .authorizationRequestRepository(cookieAuthorizationRequestRepository())
                .and()
                    .userInfoEndpoint()
                        .userService(customOAuth2UserService)
                .and()
                    .successHandler(oAuth2AuthenticationSuccessHandler)
                    .failureHandler(oAuth2AuthenticationFailureHandler);
        http.addFilterBefore(tokenAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
    }
}
