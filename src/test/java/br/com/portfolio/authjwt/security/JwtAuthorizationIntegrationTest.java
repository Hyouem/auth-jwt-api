package br.com.portfolio.authjwt.security;

import br.com.portfolio.authjwt.user.Role;
import br.com.portfolio.authjwt.user.User;
import br.com.portfolio.authjwt.user.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.time.Instant;
import java.util.UUID;

import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
class JwtAuthorizationIntegrationTest {

    @Autowired private WebApplicationContext context;
    @Autowired private UserRepository repository;
    @Autowired private PasswordEncoder passwordEncoder;
    @Autowired private JwtEncoder encoder;
    @Autowired private JwtService jwtService;

    private MockMvc mvc() {
        return MockMvcBuilders.webAppContextSetup(context)
                .apply(springSecurity())
                .build();
    }

    private User createUser(Role role) {
        return repository.saveAndFlush(new User(
                UUID.randomUUID() + "@example.com",
                passwordEncoder.encode("StrongPassword123!"),
                role
        ));
    }

    private String token(
            User user,
            Instant issuedAt,
            Instant expiresAt,
            String issuer
    ) {
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(issuer)
                .subject(user.getId().toString())
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .claim("role", user.getRole().name())
                .build();

        return encoder.encode(JwtEncoderParameters.from(
                JwsHeader.with(MacAlgorithm.HS256).build(),
                claims
        )).getTokenValue();
    }

    @Test
    void anonymousCannotReadProfile() throws Exception {
        mvc().perform(get("/api/users/me"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void userCanReadOwnProfileWithoutPassword() throws Exception {
        User user = createUser(Role.USER);

        mvc().perform(get("/api/users/me")
                        .header(
                                "Authorization",
                                "Bearer " + jwtService.generateToken(user)
                        ))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value(user.getEmail()))
                .andExpect(jsonPath("$.role").value("USER"))
                .andExpect(jsonPath("$.passwordHash").doesNotExist());
    }

    @Test
    void userCannotAccessAdminEndpoint() throws Exception {
        User user = createUser(Role.USER);

        mvc().perform(get("/api/admin/status")
                        .header(
                                "Authorization",
                                "Bearer " + jwtService.generateToken(user)
                        ))
                .andExpect(status().isForbidden());
    }

    @Test
    void adminCanAccessAdminEndpoint() throws Exception {
        User admin = createUser(Role.ADMIN);

        mvc().perform(get("/api/admin/status")
                        .header(
                                "Authorization",
                                "Bearer " + jwtService.generateToken(admin)
                        ))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status")
                        .value("ADMIN_ACCESS_GRANTED"));
    }

    @Test
    void anonymousCannotAccessAdminEndpoint() throws Exception {
        mvc().perform(get("/api/admin/status"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void tamperedTokenIsRejected() throws Exception {
        User user = createUser(Role.USER);
        String valid = jwtService.generateToken(user);
        String[] parts = valid.split("\\.");

        String tampered = parts[0] + "." + parts[1] + "." +
                (parts[2].charAt(0) == 'A' ? 'B' : 'A') +
                parts[2].substring(1);

        mvc().perform(get("/api/users/me")
                        .header("Authorization", "Bearer " + tampered))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void expiredTokenIsRejected() throws Exception {
        User user = createUser(Role.USER);

        String expired = token(
                user,
                Instant.now().minusSeconds(3600),
                Instant.now().minusSeconds(1800),
                "https://auth-jwt-api.local"
        );

        mvc().perform(get("/api/users/me")
                        .header("Authorization", "Bearer " + expired))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void wrongIssuerIsRejected() throws Exception {
        User user = createUser(Role.USER);

        String wrongIssuer = token(
                user,
                Instant.now(),
                Instant.now().plusSeconds(900),
                "https://untrusted.example"
        );

        mvc().perform(get("/api/users/me")
                        .header("Authorization", "Bearer " + wrongIssuer))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void deletedUserCannotReadProfileWithPreviouslyIssuedToken()
            throws Exception {
        User user = createUser(Role.USER);
        String jwt = jwtService.generateToken(user);

        repository.deleteById(user.getId());
        repository.flush();

        mvc().perform(get("/api/users/me")
                        .header("Authorization", "Bearer " + jwt))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void unknownRouteIsNotAccessible() throws Exception {
        User user = createUser(Role.USER);

        mvc().perform(get("/api/internal/secret")
                        .header(
                                "Authorization",
                                "Bearer " + jwtService.generateToken(user)
                        ))
                .andExpect(status().isForbidden());
    }
}