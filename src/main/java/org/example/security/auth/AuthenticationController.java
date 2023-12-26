package org.example.security.auth;

import lombok.RequiredArgsConstructor;
import org.example.security.auth.dao.JwtAuthenticationResponse;
import org.example.security.auth.dao.SignUpRequest;
import org.example.security.auth.dao.LogInRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthenticationService authenticationService;

    @PostMapping("/signup")
    public ResponseEntity<JwtAuthenticationResponse> signup(@RequestBody SignUpRequest request) {
        return ResponseEntity.ok(authenticationService.signup(request));
    }

    @PostMapping("/login")
    public ResponseEntity<JwtAuthenticationResponse> login(@RequestBody LogInRequest request) {
        return ResponseEntity.ok(authenticationService.login(request));
    }

}
