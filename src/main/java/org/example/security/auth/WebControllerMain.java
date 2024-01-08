package org.example.security.auth;


import lombok.RequiredArgsConstructor;
import org.example.features.UserRepository;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.security.Principal;

@Controller
@RequiredArgsConstructor
@RequestMapping("/url")
public class WebControllerMain {
    private final UserRepository userRepository;

    @GetMapping("/main")
    public String mainPage(Principal principal) {
        return "main";
    }


}
