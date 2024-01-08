create TABLE users(
    id           BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    username  VARCHAR(255) UNIQUE,
    password     VARCHAR(100) NOT NULL,
    token        VARCHAR(255) UNIQUE
);