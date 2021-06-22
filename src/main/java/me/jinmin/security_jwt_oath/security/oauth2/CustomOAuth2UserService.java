package me.jinmin.security_jwt_oath.security.oauth2;

import lombok.RequiredArgsConstructor;
import me.jinmin.security_jwt_oath.domain.AuthProvider;
import me.jinmin.security_jwt_oath.domain.User;
import me.jinmin.security_jwt_oath.exception.OAuth2AuthenticationProcessingException;
import me.jinmin.security_jwt_oath.repository.UserRepository;
import me.jinmin.security_jwt_oath.security.UserPrincipal;
import me.jinmin.security_jwt_oath.security.oauth2.user.OAuth2UserInfo;
import me.jinmin.security_jwt_oath.security.oauth2.user.OAuth2UserInfoFactory;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.Optional;

/**
 * UserPrincipleDetailsService 클래스의 역할, User 정보를 가져온다.
 * 가져온 User의 정보를 UserPrinciple 클래스로 변경해 Spring Security로 전달.
 */
@RequiredArgsConstructor
@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    /**
     * OAuth2 공급자로부터 Access Token을 받은 이후 호출
     * If, 동일한 이메일이 DB에 존재하지 않을 경우 사용자 정보를 등록하고
     * 존재하면 사용자 정보 업데이트
     */
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        try {
            return processOAuthUser(userRequest, oAuth2User);
        } catch (AuthenticationException e) {
            throw e;
        } catch (Exception e) {
            throw new InternalAuthenticationServiceException(e.getMessage(), e.getCause());
        }
    }

    /**
     * 사용자 정보 추출
     */
    private OAuth2User processOAuthUser(OAuth2UserRequest userRequest, OAuth2User oAuth2User) {
        OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfoFactory
                .getOAuth2UserInfo(userRequest.getClientRegistration().getRegistrationId(), oAuth2User.getAttributes());

        if (StringUtils.isEmpty(oAuth2UserInfo.getEmail())) {
            throw new OAuth2AuthenticationProcessingException("OAuth2 공급자(구글, 네이버 등)에서 이메일을 찾을 수 없습니다.");
        }

        Optional<User> userOptional = userRepository.findByEmail(oAuth2UserInfo.getEmail());
        User user;

        if (userOptional.isPresent()) {
            user = userOptional.get();

            if (!user.getProvider().equals(AuthProvider.valueOf(userRequest.getClientRegistration().getRegistrationId()))) {
                throw new OAuth2AuthenticationProcessingException(user.getProvider() + "계정을 사용하기 위해서 로그인이 필요합니다.");
            }
            user = updateExistingUser(user, oAuth2UserInfo);

        } else {
            user = registerNewUser(userRequest, oAuth2UserInfo);
        }
        return UserPrincipal.create(user);
    }

    //DB에 없을 때, 등록
    private User registerNewUser(OAuth2UserRequest userRequest, OAuth2UserInfo oAuth2UserInfo) {
        return userRepository.save(
                User.builder()
                        .name(oAuth2UserInfo.getName())
                        .email(oAuth2UserInfo.getEmail())
                        .imageUrl(oAuth2UserInfo.getImageUrl())
                        .provider(AuthProvider.valueOf(userRequest.getClientRegistration().getRegistrationId()))
                        .providerId(oAuth2UserInfo.getId())
                        .build()
        );
    }

    //DB에 없을 때, 수정
    private User updateExistingUser(User existingUser, OAuth2UserInfo oAuth2UserInfo) {
        return userRepository.save(
                existingUser.update(oAuth2UserInfo.getName(), oAuth2UserInfo.getImageUrl()));
    }
}
