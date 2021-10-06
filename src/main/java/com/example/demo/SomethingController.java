package com.example.demo;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.security.Principal;

@Controller
public class SomethingController {

    @GetMapping("/something")
    @ResponseBody
    public String something(Principal principal) {
        return "index";
    }

}
