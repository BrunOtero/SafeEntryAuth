package com.safeentry.Auth.model;

import jakarta.persistence.*; // Use jakarta.persistence para Spring Boot 3+
// import org.hibernate.annotations.GenericGenerator;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import com.safeentry.Auth.dto.RegisterRequest;

import java.time.LocalDateTime;
import java.util.UUID; 

@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID) 
    @JdbcTypeCode(SqlTypes.UUID)
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    @Column(name = "nome", nullable = false, length = 100)
    private String nome;

    @Column(name = "email", nullable = false, unique = true, length = 100)
    private String email;

    @Column(name = "senha_hash", nullable = false)
    private String senhaHash; // Corresponde a 'senha_hash' no banco de dados

    @Enumerated(EnumType.STRING) // Armazena o enum como String no banco de dados
    @Column(name = "tipo_usuario", nullable = false, length = 20)
    private UserType tipoUsuario;

    @Column(name = "apartamento", length = 10)
    private String apartamento;

    @Column(name = "ativo")
    private Boolean ativo = true;

    @Column(name = "criado_em", updatable = false)
    private LocalDateTime criadoEm = LocalDateTime.now();

    public User() {}

    public User(String nome, String email, String senhaHash, UserType tipoUsuario) {
        this.nome = nome;
        this.email = email;
        this.senhaHash = senhaHash;
        this.tipoUsuario = tipoUsuario;
    }

    public User(RegisterRequest user) {
        this.nome = user.getNome();
        this.email = user.getEmail();
        this.senhaHash = user.getSenha();
        this.tipoUsuario = user.getTipoUsuario();
        this.apartamento = user.getApartamento();
    }

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

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

    public String getSenhaHash() {
        return senhaHash;
    }

    public void setSenhaHash(String senhaHash) {
        this.senhaHash = senhaHash;
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

    public LocalDateTime getCriadoEm() {
        return criadoEm;
    }

    public void setCriadoEm(LocalDateTime criadoEm) {
        this.criadoEm = criadoEm;
    }

    @Override
    public String toString() {
        return "User{" +
               "id=" + id +
               ", nome='" + nome + '\'' +
               ", email='" + email + '\'' +
               ", tipoUsuario=" + tipoUsuario +
               ", apartamento='" + apartamento + '\'' +
               ", ativo=" + ativo +
               ", criadoEm=" + criadoEm +
               '}';
    }
}