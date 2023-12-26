package org.example.features;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.management.relation.Role;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;


@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository repository;

    public void add(UserDto userDto) {
        User user = new User();

        user.setUsername(userDto.getUsername());
        user.setPassword(userDto.getPassword());
        user.setToken(userDto.getToken());

        repository.save(user);
    }

    public List<UserDto> getList() {
        return UserDto.from(repository.findAll());
    }

    public void delete(Long id) {
        repository.deleteById(id);
    }

    public void update(UserDto userDto) {
        User user = repository.findById(userDto.getId()).orElseThrow();

        user.setUsername(userDto.getUsername());
        user.setPassword(userDto.getPassword());
        user.setToken(userDto.getToken());

        repository.save(user);
    }

}