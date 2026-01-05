package com.example.auth.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.auth.dto.SignupRequest;
import com.example.auth.entity.AppUser;
import com.example.auth.repository.UserRepository;



@RestController
@RequestMapping("/auth")
public class SignupController {

    private final UserRepository repo;
    private final PasswordEncoder encoder;

    public SignupController(UserRepository repo, PasswordEncoder encoder) {
        this.repo = repo;
        this.encoder = encoder;
    }

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@RequestBody SignupRequest req) {

        if (repo.findByUsername(req.getUsername()).isPresent()) {
            return ResponseEntity.badRequest().body("User exists");
        }

        AppUser user = new AppUser();
        user.setUsername(req.getUsername());
        user.setPassword(encoder.encode(req.getPassword()));
        user.setRole(req.getRole());

        repo.save(user);
        return ResponseEntity.ok("User created");
    }
}
