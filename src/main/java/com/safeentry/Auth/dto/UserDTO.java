package com.safeentry.Auth.dto;

import com.safeentry.Auth.model.User;
import com.safeentry.Auth.model.UserType;

public class UserDTO {
    private String nome;
    private String email;
    private UserType tipoUsuario;
    private String apartamento;
    private Boolean ativo = true;

    public UserDTO() {};

    public UserDTO(User user) {
        this.nome = user.getNome();
        this.email = user.getEmail();
        this.tipoUsuario = user.getTipoUsuario();
        this.apartamento = user.getApartamento();
        this.ativo = user.getAtivo();
    };

    public UserDTO(String nome, String email, UserType tipoUsuario, String apartamento, Boolean ativo) {
        this.nome = nome;
        this.email = email;
        this.tipoUsuario = tipoUsuario;
        this.apartamento = apartamento;
        this.ativo = ativo;
    };

    public String getNome() {
        return nome;
    }

    public void setNome(String nome) {
        this.nome = nome;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public UserType getTipoUsuario() {
        return tipoUsuario;
    }

    public void setTipoUsuario(UserType tipoUsuario) {
        this.tipoUsuario = tipoUsuario;
    }

    public String getApartamento() {
        return apartamento;
    }

    public void setApartamento(String apartamento) {
        this.apartamento = apartamento;
    }

    public Boolean getAtivo() {
        return ativo;
    }

    public void setAtivo(Boolean ativo) {
        this.ativo = ativo;
    }

    @Override
    public String toString() {
        return "User{" +
               "nome='" + nome + '\'' +
               ", email='" + email + '\'' +
               ", tipoUsuario=" + tipoUsuario +
               ", apartamento='" + apartamento + '\'' +
               ", ativo=" + ativo +
               '}';
    }
}
