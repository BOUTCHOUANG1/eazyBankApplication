package com.nathan.springsecurity.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ContactController {
    @GetMapping("/welcome")
    public String welcomeMessage() {
        return "Welcome to Spring Security with security REST API!";
    }
}
