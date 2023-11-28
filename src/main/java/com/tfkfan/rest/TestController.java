package com.tfkfan.rest;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author Baltser Artem tfkfan
 */
@RestController
@RequestMapping("/api")
public class TestController {
    @GetMapping("/test")
    public String testMethod() {
        return "VERIFIED";
    }
}
