package com.openclassrooms.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SpringSecurityConfig {
	
	@Autowired
	private CustomUserDetailsService customUserDetailService;
	
	
	
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		return http.authorizeHttpRequests(auth -> {
			auth.requestMatchers("/admin").hasRole("ADMIN");
			auth.requestMatchers("/user").hasRole("USER");
			auth.requestMatchers("/internaute").hasRole("INTERNAUTE");
			auth.anyRequest().authenticated();
		}).formLogin(Customizer.withDefaults()).build();
	}

	@Bean
	public UserDetailsService users() {
		UserDetails user = User.builder()
				.username("user")
				.password(passwordEncoder()
				.encode("user"))
				.roles("USER","INTERNAUTE")
				.build();
		UserDetails admin = User.builder()
				.username("administrateur")
				.password(passwordEncoder()
				.encode("pauli#137"))
				.roles("USER","ADMIN","INTERNAUTE")
				.build();
		UserDetails user2 = User.builder()
				.username("toto")
				.password(passwordEncoder()
				.encode("winchester#73"))
				.roles("USER","INTERNAUTE")
				.build();
		UserDetails lostone= User.builder()
				.username("dupont")
				.password(passwordEncoder()
				.encode("dupont"))
				.roles("INTERNAUTE")
				.build();
		return new InMemoryUserDetailsManager(user,admin,user2,lostone);
	}
	
	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	public AuthenticationManager authenticationManager(HttpSecurity http, BCryptPasswordEncoder bCryptPasswordEncoder) throws Exception {
		AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
	authenticationManagerBuilder.userDetailsService(customUserDetailService).passwordEncoder(bCryptPasswordEncoder);
		return authenticationManagerBuilder.build();
	}
}

