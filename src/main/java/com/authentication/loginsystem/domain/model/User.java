package com.authentication.loginsystem.domain.model;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Entity
public class User {

    @Id
    private Long id;

    private String name;
    private String email;
    private String password;
    private boolean active;

}
