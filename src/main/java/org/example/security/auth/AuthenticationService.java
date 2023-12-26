package org.example.security.auth;

import lombok.RequiredArgsConstructor;
import org.example.features.User;
import org.example.features.UserRepository;
import org.example.features.UserService;
import org.example.security.auth.dao.JwtAuthenticationResponse;
import org.example.security.auth.dao.LogInRequest;
import org.example.security.auth.dao.SignUpRequest;
import org.example.security.jwt.JwtService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final CustomUserDetailsService customUserDetailsService;
    private final UserRepository userRepository;
    public static final int PASSWORD_REQUIRED_LENGTH = 8;

    public JwtAuthenticationResponse signup(SignUpRequest request) {
        if (!isValidPassword(request.getPassword())) {
            String errorMessage = "Invalid password. Password must be at least 8 characters long and include at least one digit, one uppercase letter, and one lowercase letter.";
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new JwtAuthenticationResponse(HttpStatus.BAD_REQUEST.value(), errorMessage, null)).getBody();
        }
        if (!request.getPassword().equals(request.getConfirmPassword())) {
            String errorMessage = "Password and confirm password do not match";
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new JwtAuthenticationResponse(HttpStatus.BAD_REQUEST.value(), errorMessage, null)).getBody();
        }
        User newUser = new User();
        newUser.setUsername(request.getUsername());
        newUser.setPassword(passwordEncoder.encode(request.getPassword()));
        var jwt = jwtService.generateToken(new CustomUserDetails(newUser));
        newUser.setToken(jwt);
        userRepository.save(newUser);
        return JwtAuthenticationResponse.builder()
                .status(HttpStatus.OK.value())
                .message("Success")
                .token(jwt)
                .build();
    }

    public JwtAuthenticationResponse login(LogInRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));
        var user = customUserDetailsService.loadUserByUsername(request.getUsername());
        var jwt = jwtService.generateToken(user);
        return JwtAuthenticationResponse.builder()
                .status(HttpStatus.OK.value())
                .message("Success")
                .token(jwt)
                .build();
    }

    public static boolean isValidPassword(String password) {
        return (password.length() >= PASSWORD_REQUIRED_LENGTH)
                && (password.replaceAll("\\d", "").length() != password.length())
                && (!password.toLowerCase().equals(password))
                && (!password.toUpperCase().equals(password));
    }
}
