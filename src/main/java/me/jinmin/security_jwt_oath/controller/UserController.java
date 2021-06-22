package me.jinmin.security_jwt_oath.controller;

import lombok.RequiredArgsConstructor;
import me.jinmin.security_jwt_oath.domain.User;
import me.jinmin.security_jwt_oath.exception.ResourceNotFoundException;
import me.jinmin.security_jwt_oath.repository.UserRepository;
import me.jinmin.security_jwt_oath.security.CurrentUser;
import me.jinmin.security_jwt_oath.security.UserPrincipal;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
public class UserController {

    private final UserRepository userRepository;

    @GetMapping("/user/me")
    @PreAuthorize("hasRole('USER')")
    public User getCurrentUser(@CurrentUser UserPrincipal userPrincipal) {
        return userRepository.findById(userPrincipal.getId())
                .orElseThrow(() -> new ResourceNotFoundException("User", "id", userPrincipal.getId()));
    }
}
