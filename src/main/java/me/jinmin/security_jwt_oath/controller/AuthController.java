package me.jinmin.security_jwt_oath.controller;

import lombok.RequiredArgsConstructor;
import me.jinmin.security_jwt_oath.controller.dto.ApiResponse;
import me.jinmin.security_jwt_oath.controller.dto.AuthResponse;
import me.jinmin.security_jwt_oath.controller.dto.LoginRequest;
import me.jinmin.security_jwt_oath.controller.dto.SignUpRequest;
import me.jinmin.security_jwt_oath.domain.AuthProvider;
import me.jinmin.security_jwt_oath.domain.User;
import me.jinmin.security_jwt_oath.exception.BadRequestException;
import me.jinmin.security_jwt_oath.repository.UserRepository;
import me.jinmin.security_jwt_oath.security.TokenProvider;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.validation.Valid;
import java.net.URI;

/**
 * 외부 도메인인 클라이언트가 애플리케이션 서버에 자원을 요청하기 위해서 CORS를 허용해야한다.
 */
@RequiredArgsConstructor
@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenProvider tokenProvider;

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getEmail(),
                        loginRequest.getPassword()
                )
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);

        String token = tokenProvider.createToken(authentication);

        return ResponseEntity.ok(new AuthResponse(token));
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@RequestBody SignUpRequest signUpRequest) {
        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            throw new BadRequestException("해당 이메일을 이미 사용중입니다.");
        }

        User result = userRepository.save(User.builder()
                .name(signUpRequest.getName())
                .email(signUpRequest.getEmail())
                .password(passwordEncoder.encode(signUpRequest.getPassword()))
                .provider(AuthProvider.local)
                .build());

        URI location = ServletUriComponentsBuilder
                .fromCurrentContextPath().path("/user/me")
                .buildAndExpand(result.getId()).toUri();

        return ResponseEntity.created(location)
                .body(new ApiResponse(true, "성공적으로 계정이 생성됐습니다."));
    }
}
