package com.example.authpractice.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter{

    // this service class will interact with the token to extract the user's email
    private final JWTService jwtService;

    @Override
    protected void doFilterInternal(
            // this param represents the user request
            @NonNull HttpServletRequest request,
            // this param represents the response sent back by the server
            @NonNull HttpServletResponse response,
            // this param provides a way for Spring to chain together filters
            // these filters are how we are going to create the pipeline to authenticate requests
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;
        if(authHeader == null || !authHeader.startsWith("Bearer ")){
            filterChain.doFilter(request, response);
            return;
        }
        // grabs the token from the auth header after "Bearer "
        jwt = authHeader.substring(7);
        userEmail = jwtService.extractUsername(jwt);
    }
}
