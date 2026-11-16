package br.com.portfolio.authjwt.auth;

import br.com.portfolio.authjwt.user.Role;
import br.com.portfolio.authjwt.user.User;

import java.util.UUID;

public record UserResponse(
        UUID id,
        String email,
        Role role
) {
    public static UserResponse from(User user) {
        return new UserResponse(
                user.getId(),
                user.getEmail(),
                user.getRole()
        );
    }
}