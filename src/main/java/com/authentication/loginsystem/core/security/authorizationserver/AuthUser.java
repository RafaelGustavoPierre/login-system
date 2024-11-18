package com.authentication.loginsystem.core.security.authorizationserver;

import lombok.Getter;
import org.springframework.security.core.userdetails.User;

import java.util.Collections;

@Getter
public class AuthUser extends User {

    private String fullName;

    public AuthUser(com.authentication.loginsystem.domain.model.User user) {
        super(user.getEmail(), user.getPassword(), Collections.emptyList());

        this.fullName = user.getName();
    }

}
