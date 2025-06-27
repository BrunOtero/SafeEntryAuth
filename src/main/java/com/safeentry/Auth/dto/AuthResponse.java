package com.safeentry.Auth.dto;

// Objeto para respostas de login (contém o token JWT)
public class AuthResponse {
    private String token;
    private String tipoUsuario;
    private String email;
    private String nome;

    public AuthResponse(String token, String tipoUsuario, String email, String nome) {
        this.token = token;
        this.tipoUsuario = tipoUsuario;
        this.email = email;
        this.nome = nome;
    }

    // Getters
    public String getToken() {
        return token;
    }

    public String getTipoUsuario() {
        return tipoUsuario;
    }

    public String getEmail() {
        return email;
    }

    public String getNome() {
        return nome;
    }
}