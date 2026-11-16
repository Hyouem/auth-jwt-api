package br.com.portfolio.authjwt.auth;

import br.com.portfolio.authjwt.user.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import tools.jackson.databind.ObjectMapper;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
class LoginIntegrationTest {

    @Autowired
    private WebApplicationContext context;

    @Autowired
    private UserRepository repository;

    @Autowired
    private JwtDecoder decoder;

    @Autowired
    private ObjectMapper objectMapper;

    private MockMvc mvc() {
        return MockMvcBuilders.webAppContextSetup(context)
                .apply(org.springframework.security.test.web.servlet.setup
                        .SecurityMockMvcConfigurers.springSecurity())
                .build();
    }

    private String json(String email, String password) {
        return String.format(
                "{\"email\":\"%s\",\"password\":\"%s\"}",
                email,
                password
        );
    }

    @Test
    void shouldIssueValidJwtAfterLogin() throws Exception {
        String email = UUID.randomUUID() + "@example.com";
        String password = "StrongPassword123!";

        mvc().perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(email, password)))
                .andExpect(status().isCreated());

        String response = mvc().perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(email.toUpperCase(), password)))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();

        var body = objectMapper.readTree(response);

        assertThat(body.get("tokenType").asText()).isEqualTo("Bearer");
        assertThat(body.get("expiresIn").asLong()).isEqualTo(900L);

        String token = body.get("accessToken").asText();
        var jwt = decoder.decode(token);
        var user = repository.findByEmail(email).orElseThrow();

        assertThat(jwt.getSubject()).isEqualTo(user.getId().toString());
        assertThat(jwt.getClaimAsString("role")).isEqualTo("USER");
        assertThat(jwt.getIssuer().toString())
                .isEqualTo("https://auth-jwt-api.local");
        assertThat(jwt.getExpiresAt()).isAfter(Instant.now());
    }

    @Test
    void shouldRejectWrongPassword() throws Exception {
        String email = UUID.randomUUID() + "@example.com";

        mvc().perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(email, "StrongPassword123!")))
                .andExpect(status().isCreated());

        mvc().perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(email, "WrongPassword123!")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void shouldRejectUnknownEmail() throws Exception {
        mvc().perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(
                                UUID.randomUUID() + "@example.com",
                                "StrongPassword123!"
                        )))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void shouldRejectBlankCredentials() throws Exception {
        mvc().perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json("", "")))
                .andExpect(status().isBadRequest());
    }
}