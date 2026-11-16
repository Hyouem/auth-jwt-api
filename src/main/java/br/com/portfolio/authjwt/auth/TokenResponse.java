package br.com.portfolio.authjwt.auth;

public record TokenResponse(
        String accessToken,
        String tokenType,
        long expiresIn
) {
}