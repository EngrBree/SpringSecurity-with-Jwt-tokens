package com.example.springjwt.user;

import lombok.Getter;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.security.Permission;
import java.util.Set;
import java.util.stream.Collectors;

public enum UserRole {
    USER,
    ADMIN;


}
