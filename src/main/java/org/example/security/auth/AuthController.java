package org.example.security.auth;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

import org.example.security.auth.dao.JwtAuthenticationResponse;
import org.example.security.auth.dao.LogInRequest;
import org.example.security.auth.dao.SignUpRequest;
import org.example.security.config.CookieService;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.net.URISyntaxException;


@Controller
@RequiredArgsConstructor
@RequestMapping("/main")
public class AuthController {
    private final AuthenticationService authenticationService;
    private final CookieService cookieService;

    @GetMapping("/signup")
    public String signup(Model model) {
        model.addAttribute("signupRequest", new SignUpRequest());
        return "registration";
    }

    @PostMapping("/signup")
    public String signup(@ModelAttribute("signupRequest") SignUpRequest signupRequest, Model model) {
        JwtAuthenticationResponse responseEntity = authenticationService.signup(signupRequest);
        return "redirect:/main/login";
    }

    @GetMapping("/login")
    public String login(Model model) {
        model.addAttribute("loginRequest", new LogInRequest());
        return "login";
    }


    @PostMapping("/login")
    public String login(@ModelAttribute("loginRequest") LogInRequest logInRequest, Model model, HttpServletResponse response) throws IOException, URISyntaxException {
        JwtAuthenticationResponse responseEntity = authenticationService.login(logInRequest);

        Cookie tokenCookie = cookieService.createCookie("token", responseEntity.getToken());
        response.addCookie(tokenCookie);

        return "redirect:/url/main";
    }
    @GetMapping ("/logout")
    public String logout (){
        SecurityContextHolder.getContext().setAuthentication(null);
        return "redirect:main/login";
    }

}
