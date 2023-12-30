package org.example.security.auth;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.example.security.auth.dao.JwtAuthenticationResponse;
import org.example.security.auth.dao.LogInRequest;
import org.example.security.auth.dao.SignUpRequest;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthController {
    private final AuthenticationService authenticationService;

    @GetMapping("/signup")
    public String signup(Model model) {
        model.addAttribute("signupRequest", new SignUpRequest());
        return "registration";
    }

    @PostMapping("/signup")
    public String signup(@ModelAttribute("signupRequest") SignUpRequest signupRequest, Model model) {
        JwtAuthenticationResponse responseEntity = authenticationService.signup(signupRequest);
        return "redirect:/auth/login";
    }

    @GetMapping("/login")
    public String login(Model model) {
        model.addAttribute("loginRequest", new LogInRequest());
        return "login";
    }

    @PostMapping("/login")
    public String login(@ModelAttribute("loginRequest") LogInRequest logInRequest,Model model, HttpServletResponse response) {
        JwtAuthenticationResponse responseEntity = authenticationService.login(logInRequest);

        if (responseEntity.getToken() != null && !responseEntity.getToken().isEmpty()) {
//            HttpHeaders headers = new HttpHeaders();
//            headers.add("Authorization", "Bearer " + responseEntity.getToken());
//            HttpEntity request = new HttpEntity(headers);
            System.out.println(responseEntity);
            response.addHeader("Authorization", "Bearer " + responseEntity.getToken());
        }

        return "redirect:/url/main";
    }
}
