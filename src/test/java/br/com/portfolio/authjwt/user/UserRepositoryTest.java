package br.com.portfolio.authjwt.user;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest
@Transactional
class UserRepositoryTest {

    @Autowired
    private UserRepository repository;

    @Test
    void shouldSaveAndFindUserByEmail() {
        User user = new User(
                "TEST@EXAMPLE.COM",
                "bcrypt-placeholder",
                Role.USER
        );

        repository.saveAndFlush(user);

        assertThat(repository.findByEmail("test@example.com"))
                .isPresent()
                .get()
                .extracting(User::getRole)
                .isEqualTo(Role.USER);
    }

    @Test
    void shouldDetectExistingEmail() {
        repository.saveAndFlush(
                new User("exists@example.com", "hash", Role.USER)
        );

        assertThat(repository.existsByEmail("exists@example.com"))
                .isTrue();

        assertThat(repository.existsByEmail("missing@example.com"))
                .isFalse();
    }

    @Test
    void shouldRejectDuplicateEmail() {
        repository.saveAndFlush(
                new User("duplicate@example.com", "hash1", Role.USER)
        );

        assertThatThrownBy(() -> repository.saveAndFlush(
                new User("duplicate@example.com", "hash2", Role.USER)
        )).isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);
    }

    @Test
    void shouldPersistAdminRole() {
        User saved = repository.saveAndFlush(
                new User("admin@example.com", "hash", Role.ADMIN)
        );

        assertThat(repository.findById(saved.getId()))
                .isPresent()
                .get()
                .extracting(User::getRole)
                .isEqualTo(Role.ADMIN);
    }

    @Test
    void shouldRejectInvalidConstructorArguments() {
        assertThatThrownBy(() -> new User(" ", "hash", Role.USER))
                .isInstanceOf(IllegalArgumentException.class);

        assertThatThrownBy(() -> new User("valid@example.com", "", Role.USER))
                .isInstanceOf(IllegalArgumentException.class);

        assertThatThrownBy(() -> new User("valid@example.com", "hash", null))
                .isInstanceOf(IllegalArgumentException.class);
    }
}