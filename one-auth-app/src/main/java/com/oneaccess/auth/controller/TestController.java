package com.oneaccess.auth.springcustomizedstarterexample.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class TestController {

    @GetMapping("/")
    @ResponseBody
    public String hello() {
        return "Hello! World";
    }
}
