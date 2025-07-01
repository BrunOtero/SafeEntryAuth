package com.safeentry.Auth.controller;

import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import com.safeentry.Auth.dto.AuthRequest;
import com.safeentry.Auth.dto.AuthResponse;
import com.safeentry.Auth.dto.RegisterRequest;
import com.safeentry.Auth.dto.UserDTO;
import com.safeentry.Auth.model.User;
import com.safeentry.Auth.service.UserService;
import com.safeentry.Auth.util.JwtUtil;

import java.util.Optional;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserService userService;
    private final JwtUtil jwtUtil;
    private final AuthenticationManager authenticationManager;

    public AuthController(UserService userService, JwtUtil jwtUtil, AuthenticationManager authenticationManager) {
        this.userService = userService;
        this.jwtUtil = jwtUtil;
        this.authenticationManager = authenticationManager;
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody RegisterRequest newUser) {
        try {
            User registeredUser = userService.registerNewUser(newUser);
            UserDTO registeredUserDTO = new UserDTO(registeredUser);
            return ResponseEntity.status(HttpStatus.CREATED).body(registeredUserDTO);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Erro ao registrar usuário: " + e.getMessage());
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> createAuthenticationToken(@Valid @RequestBody AuthRequest authenticationRequest) throws Exception {
        try {
            Authentication authenticate = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authenticationRequest.getEmail(), authenticationRequest.getSenha())
            );

            Optional<User> userOptional = userService.findByEmail(authenticationRequest.getEmail());

            if (userOptional.isPresent()) {
                User user = userOptional.get();
                // Passar o user.getId() para o generateToken
                final String jwt = jwtUtil.generateToken(user.getId(), user.getEmail(), user.getTipoUsuario().name(), user.getNome());
                return ResponseEntity.ok(new AuthResponse(jwt, user.getTipoUsuario().name(), user.getEmail(), user.getNome()));
            } else {
                throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Usuário não encontrado após autenticação bem-sucedida.");
            }

        } catch (BadCredentialsException e) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Email ou senha inválidos.");
        } catch (Exception e) {
            e.printStackTrace();
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Erro durante a autenticação: " + e.getMessage());
        }
    }

    @GetMapping("/me")
    public ResponseEntity<?> getUserDetails(Authentication authentication) {
        if (authentication != null && authentication.getPrincipal() instanceof UserDetails) {
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            String email = userDetails.getUsername();

            Optional<User> userOptional = userService.findByEmail(email);
            if (userOptional.isPresent()) {
                User user = userOptional.get();
                UserDTO userDTO = new UserDTO(user);
                return ResponseEntity.ok(userDTO);
            }
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Nenhum usuário autenticado encontrado.");
    }
}