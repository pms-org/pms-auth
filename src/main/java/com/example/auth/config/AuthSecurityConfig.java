package com.example.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@Order(2)
public class AuthSecurityConfig {

    @Bean
    SecurityFilterChain authSecurityFilterChain(HttpSecurity http) throws Exception {

        http
            .securityMatcher("/auth/**")
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/auth/signup").permitAll()
                .anyRequest().authenticated()
            );

        return http.build();
    }
}
