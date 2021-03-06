<?php
/**
 * Created by PhpStorm.
 * User: nagyatka
 * Date: 2017. 09. 23.
 * Time: 10:03
 */

namespace KodiSecurity\Model\User;


class AnonymUser implements AuthenticatedUserInterface
{
    public function getHashedPassword(): ?string
    {
        return null;
    }

    public function clear(): void
    {

    }

    public function getUsername(): ?string
    {
        return null;
    }

    public function isValidUsername(): bool
    {
        return false;
    }

    public function getUserId(): ?int
    {
        return null;
    }

    public function getRoles(): array
    {
        return [Role::ANON_USER];
    }

    public function hasRole($role): bool
    {
        return $role === Role::ANON_USER;
    }

    public static function getUserByUsername(string $username): AuthenticatedUserInterface
    {
        return new AnonymUser();
    }

    public static function getUserByEmail(string $email): AuthenticatedUserInterface
    {
        return new AnonymUser();
    }

    public static function getUserFromSession(int $userId, string $userName)
    {
        return new AnonymUser();
    }

    public static function getUserByUserId(int $user_id): AuthenticatedUserInterface
    {
        return new AnonymUser();
    }

    public static function getUserFromSecuritySession(?int $user_id, ?string $username, ?array $roles): AuthenticatedUserInterface
    {
        return new AnonymUser();
    }
}