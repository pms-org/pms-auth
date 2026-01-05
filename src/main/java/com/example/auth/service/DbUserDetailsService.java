package com.example.auth.service;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.example.auth.entity.AppUser;
import com.example.auth.repository.UserRepository;

@Service
public class DbUserDetailsService implements UserDetailsService {

    private final UserRepository repo;

    public DbUserDetailsService(UserRepository repo) {
        this.repo = repo;
    }

    @Override
    public UserDetails loadUserByUsername(String username) {

        AppUser user = repo.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        return User.builder()
                .username(user.getUsername())
                .password(user.getPassword())
                .roles(user.getRole())
                .build();
    }
}
