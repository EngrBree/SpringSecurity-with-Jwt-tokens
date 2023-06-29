package com.example.springjwt.token;

import com.example.springjwt.user.User;
import jakarta.persistence.*;
import lombok.Builder;
import lombok.Data;
import lombok.With;

@Data
@Builder
@With
@Entity
public class Token {
    @Id
    @GeneratedValue
    public Integer id;

    @Column(unique = true)
    public String token;

    @Enumerated(EnumType.STRING)
    public TokenType tokenType = TokenType.BEARER;

    public boolean revoked;

    public boolean expired;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    public User user;
}
