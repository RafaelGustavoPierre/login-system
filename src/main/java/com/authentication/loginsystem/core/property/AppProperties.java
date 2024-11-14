package com.authentication.loginsystem.core.property;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

@Component
@Getter
@Setter
@ConfigurationProperties("loginsystem.auth")
public class AppProperties {

    private Security security;

    @Getter
    @Setter
    public static class Security {

        @NotBlank
        private String providerUrl;

        @NotBlank
        private String keypairAlias;

        @NotBlank
        private Resource jksResource;

        @NotBlank
        private String password;

    }

}
