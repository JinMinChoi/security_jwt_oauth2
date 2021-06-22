package me.jinmin.security_jwt_oath.controller.dto;

import lombok.Builder;
import lombok.Getter;

@Getter
public class SignUpRequest {

    private String name;
    private String email;
    private String password;

    @Builder
    public SignUpRequest(String name, String email, String password) {
        this.name = name;
        this.email = email;
        this.password = password;
    }
}
