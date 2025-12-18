package com.example.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

@Configuration
public class JwtCustomizerConfig {

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return context -> {

           
            if (!context.getPrincipal().getAuthorities().isEmpty()) {

                var roles = context.getPrincipal().getAuthorities()
                        .stream()
                        .map(a -> a.getAuthority())
                        .toList();

                context.getClaims().claim("roles", roles);
                context.getClaims().claim(
                        "scope",
                        roles.stream()
                             .map(r -> r.replace("ROLE_", ""))
                             .toList()
                );
            }

           
            if (AuthorizationGrantType.CLIENT_CREDENTIALS
                    .equals(context.getAuthorizationGrantType())) {

                context.getClaims().claim(
                        "scope",
                        context.getAuthorizedScopes()
                );
            }
        };
    }
}
