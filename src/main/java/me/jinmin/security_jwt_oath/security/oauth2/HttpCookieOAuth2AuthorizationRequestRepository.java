package me.jinmin.security_jwt_oath.security.oauth2;

import com.nimbusds.oauth2.sdk.util.StringUtils;
import me.jinmin.security_jwt_oath.util.CookieUtils;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * OAuth2 프로토콜은 CSRF 공격을 방지하기 위해 STATE 매개변수 사용을 권장한다.
 * 인증 과정 중 애플리케이션은 인증 요청(Authorization Request)에 이 매개 변수를 전송하고
 * OAuth2 공급자는 OAuth2 콜백에서 변경되지 않은 해당 매개변수를 반환한다.
 * 애플리케이션은 OAuth2 공급자로부터 반환된 상태의 매개변수 값과 초기에 보낸 값을 비교해 일치하지 않으면 인증 요청을 거부한다.
 *
 * 즉, 애플리케이션이 상태 매개 변수를 저장하여 추후 OAuth2 공급자에게서 반환된 상태와 비교 가능해야한다.
 * 이를 위해 쿠키에 상태 + redirect_uri를 저장하도록 설정한다.
 */
@Component
public class HttpCookieOAuth2AuthorizationRequestRepository implements
        AuthorizationRequestRepository<OAuth2AuthorizationRequest> {

    public static final String OAUTH2_AUTHORIZATION_REQUEST_NAME = "oauth2_auth_request";
    public static final String REDIRECT_URI_PARAM_COOKIE_NAME = "redirect_uri";
    private static final int cookieExpireSeconds = 180;

    @Override
    public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
        return CookieUtils.getCookie(request, OAUTH2_AUTHORIZATION_REQUEST_NAME)
                .map(cookie -> CookieUtils.deserialize(cookie, OAuth2AuthorizationRequest.class))
                .orElse(null);
    }

    @Override
    public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest,
                                         HttpServletRequest request, HttpServletResponse response) {
        if (authorizationRequest == null) {
            CookieUtils.deleteCookie(request, response, OAUTH2_AUTHORIZATION_REQUEST_NAME);
            CookieUtils.deleteCookie(request, response, REDIRECT_URI_PARAM_COOKIE_NAME);
            return;
        }
        
        CookieUtils.addCookie(response, OAUTH2_AUTHORIZATION_REQUEST_NAME,
                CookieUtils.serialize(authorizationRequest), cookieExpireSeconds);

        String redirectUriAfterLogin = request.getParameter(REDIRECT_URI_PARAM_COOKIE_NAME);
        if (StringUtils.isNotBlank(redirectUriAfterLogin)) {
            CookieUtils.addCookie(response, REDIRECT_URI_PARAM_COOKIE_NAME, redirectUriAfterLogin, cookieExpireSeconds);
        }
    }

    @Override
    public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request) {
        return this.loadAuthorizationRequest(request);
    }

    public void removeAuthorizationRequestCookies(HttpServletRequest request,
                                                                 HttpServletResponse response) {
        CookieUtils.deleteCookie(request, response, OAUTH2_AUTHORIZATION_REQUEST_NAME);
        CookieUtils.deleteCookie(request, response, REDIRECT_URI_PARAM_COOKIE_NAME);
    }
}
