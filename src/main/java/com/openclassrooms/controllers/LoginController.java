package com.openclassrooms.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginController {

	@GetMapping("/user")
	public String getUser() {
		return "welcom, user";
	}
	
	@GetMapping("/admin")
	public String getAdmin() {
		return "welcom, admin";
	}
	
	@GetMapping("/internaut")
	public String getInternaut() {
		return "welcom, internaute";
	}
}
