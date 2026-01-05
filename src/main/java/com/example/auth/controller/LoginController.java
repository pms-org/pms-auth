package com.example.auth.controller;

import java.time.Instant;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.auth.dto.LoginRequest;


@RestController
@RequestMapping("/auth")
public class LoginController {

    private final AuthenticationManager authManager;
    private final JwtEncoder jwtEncoder;

    public LoginController(AuthenticationManager authManager,
                           JwtEncoder jwtEncoder) {
        this.authManager = authManager;
        this.jwtEncoder = jwtEncoder;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest req) {

        Authentication authentication = authManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        req.getUsername(),
                        req.getPassword()
                )
        );

        Instant now = Instant.now();

        String token = jwtEncoder.encode(
                JwtEncoderParameters.from(
                        JwsHeader.with(SignatureAlgorithm.RS256).build(),
                        JwtClaimsSet.builder()
                                .issuer("http://auth:8081")
                                .subject(authentication.getName())
                                .issuedAt(now)
                                .expiresAt(now.plusSeconds(3600))
                                .claim(
                                    "roles",
                                    authentication.getAuthorities()
                                            .stream()
                                            .map(GrantedAuthority::getAuthority)
                                            .toList()
                                )
                                .build()
                )
        ).getTokenValue();

        return ResponseEntity.ok(Map.of("access_token", token));
    }
}
