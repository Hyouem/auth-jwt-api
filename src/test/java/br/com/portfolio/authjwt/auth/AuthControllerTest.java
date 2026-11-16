package br.com.portfolio.authjwt.auth;

import br.com.portfolio.authjwt.user.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
class AuthControllerTest {

    @Autowired
    private WebApplicationContext context;

    @Autowired
    private UserRepository repository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private MockMvc mvc() {
        return MockMvcBuilders
                .webAppContextSetup(context)
                .apply(org.springframework.security.test.web.servlet.setup
                        .SecurityMockMvcConfigurers.springSecurity())
                .build();
    }

    private String registrationJson(String email, String password) {
        return String.format(
                "{\"email\":\"%s\",\"password\":\"%s\"}",
                email,
                password
        );
    }

    @Test
    void shouldRegisterUserWithHashedPassword() throws Exception {
        String email = UUID.randomUUID() + "@example.com";
        String password = "StrongPassword123!";

        mvc().perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registrationJson(email, password)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.email").value(email))
                .andExpect(jsonPath("$.role").value("USER"))
                .andExpect(jsonPath("$.passwordHash").doesNotExist());

        var user = repository.findByEmail(email).orElseThrow();

        assertThat(user.getPasswordHash()).isNotEqualTo(password);
        assertThat(passwordEncoder.matches(password, user.getPasswordHash()))
                .isTrue();
    }

    @Test
    void shouldRejectDuplicateEmail() throws Exception {
        String email = UUID.randomUUID() + "@example.com";
        String request = registrationJson(email, "StrongPassword123!");

        mvc().perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(request))
                .andExpect(status().isCreated());

        mvc().perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(request))
                .andExpect(status().isConflict());
    }

    @Test
    void shouldRejectInvalidRegistration() throws Exception {
        mvc().perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registrationJson("invalid-email", "123")))
                .andExpect(status().isBadRequest());
    }

    @Test
    void shouldRejectUnauthenticatedUnknownEndpoint() throws Exception {
        mvc().perform(post("/api/protected")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isUnauthorized());
    }
}