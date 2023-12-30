package org.example.security.auth;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.example.features.User;
import org.example.features.UserRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.security.Principal;
import java.util.Optional;

@Controller
@RequiredArgsConstructor
@RequestMapping("/url")
public class WebControllerMain {
    private final UserRepository userRepository;

    @GetMapping("/main")
    public String mainPage(Principal principal, HttpServletResponse response) {
        Optional<User> byUsername = userRepository.findByUsername(principal.getName());
        User user = byUsername.get();
        System.out.println(principal.getName()+"kiuh;ihu ");
        if (user.getToken() != null) {
            response.addHeader("Authorization", "Bearer " + user.getToken());
        }
        return "main";
    }
}
