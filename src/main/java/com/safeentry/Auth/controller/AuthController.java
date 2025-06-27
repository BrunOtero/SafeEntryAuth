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

    // Endpoint para registrar um novo usuário
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

    // Endpoint para login e geração de JWT
    @PostMapping("/login")
    public ResponseEntity<?> createAuthenticationToken(@Valid @RequestBody AuthRequest authenticationRequest) throws Exception {
        try {
            // Tenta autenticar o usuário com as credenciais fornecidas
            Authentication authenticate = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authenticationRequest.getEmail(), authenticationRequest.getSenha())
            );

            // Se a autenticação for bem-sucedida, busca o usuário no banco de dados
            // Usamos Optional aqui para evitar NullPointerExceptions se o usuário não for encontrado
            Optional<User> userOptional = userService.findByEmail(authenticationRequest.getEmail());

            if (userOptional.isPresent()) {
                User user = userOptional.get(); 
                final String jwt = jwtUtil.generateToken(user.getEmail(), user.getTipoUsuario().name()); // Gera o token JWT com base no email e tipo de usuário
                return ResponseEntity.ok(new AuthResponse(jwt, user.getTipoUsuario().name(), user.getEmail(), user.getNome())); // Retorna o token e outras informações do usuário
            } else {
                throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Usuário não encontrado após autenticação bem-sucedida."); // Erro
            }

        } catch (BadCredentialsException e) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Email ou senha inválidos."); // Lança uma exceção para credenciais inválidas
        } catch (Exception e) {
            e.printStackTrace();
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Erro durante a autenticação: " + e.getMessage());
        }
    }

    // Endpoint de exemplo para obter detalhes do usuário autenticado
    @GetMapping("/me")
    public ResponseEntity<?> getUserDetails(Authentication authentication) {
        if (authentication != null && authentication.getPrincipal() instanceof UserDetails) {
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            String email = userDetails.getUsername(); // O email é o username no UserDetails

            Optional<User> userOptional = userService.findByEmail(email);
            if (userOptional.isPresent()) {
                // Retorna apenas as informações públicas do usuário
                User user = userOptional.get();
                UserDTO userDTO = new UserDTO(user);
                return ResponseEntity.ok(userDTO);
            }
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Nenhum usuário autenticado encontrado.");
    }
}