<?php

namespace KodiSecurity\Model;

/**
 * Interface UserInterface
 * @package KodiSecurity\Model
 */
interface AuthenticatedUserInterface
{
    /**
     * @return string
     */
    public function getHashedPassword(): ?string;

    /**
     * Clears every secret from the instance.
     */
    public function clear(): void;

    /**
     * Returns with the username.
     * @return string
     */
    public function getUsername(): ?string;

    /**
     * The username exists in database or not.
     *
     * @return bool
     */
    public function isValidUsername(): bool;

    /**
     * @return int
     */
    public function getUserId(): ?int;

    /**
     * @return array
     */
    public function getRoles(): array;

    /**
     * @param $role
     * @return bool
     */
    public function hasRole($role): bool;

    /**
     * @param int $user_id
     * @return AuthenticatedUserInterface
     */
    public static function getUserByUserId(int $user_id): AuthenticatedUserInterface;

    /**
     * @param string $username
     * @return AuthenticatedUserInterface
     */
    public static function getUserByUsername(string $username): AuthenticatedUserInterface;

    /**
     * @param string $email
     * @return AuthenticatedUserInterface
     */
    public static function getUserByEmail(string $email): AuthenticatedUserInterface;

    /**
     * @param int $user
     * @param string $username
     * @param array $roles
     * @return AuthenticatedUserInterface
     */
    public static function getUserFromSecuritySession(int $user, string $username, array $roles): AuthenticatedUserInterface;
}