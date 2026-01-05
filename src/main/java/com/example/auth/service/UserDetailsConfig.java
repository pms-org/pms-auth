package com.example.auth.service;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
public class UserDetailsConfig {

    @Bean
    public UserDetailsService userDetailsService() {
        return new InMemoryUserDetailsManager(
            User.withUsername("admin")
                .password("{bcrypt}$2a$10$7sYzq7rZr6JjvR0z0yYzQeHkQp0z9Jt8gZz0q0m0r9tG6p6u")
                .roles("ADMIN")
                .build()
        );
    }
}
