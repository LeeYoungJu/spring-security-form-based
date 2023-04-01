package com.yjlee.springsecuritystudy.account;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class SignInController {

    @GetMapping("/signin")
    public String signinForm() {
        return "signin";
    }

    @GetMapping("signout")
    public String signoutForm() {
        return "signout";
    }
}
