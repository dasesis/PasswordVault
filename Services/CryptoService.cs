using System;
using System.Text;
using System.Security.Cryptography;

namespace PassowrdVault.Services;

public class CryptoService
{
    private const int SaltSize = 16;
    private const int KeySize = 32; // AES-256
    private const int NonceSize = 12; // AES-GCM IV/Nonce
    private const int TagSize = 16; // Auth Tag
    private const int Pbkdf2Iterations = 300_000;

    public byte[] GenerateSalt()
    {
        return RandomNumberGenerator.GetBytes(SaltSize);
    }

    public byte[] DeriveKey(string masterPassword, byte[] salt)
    {
        return Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(masterPassword),
            salt,
            Pbkdf2Iterations,
            HashAlgorithmName.SHA256,
            KeySize
        );
    }

    public (byte[] Ciphertext, byte[] Nonce, byte[] Tag) Encrypt(byte[] plainTextBytes, byte[] key)
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceSize);
        byte[] ciphertext = new byte[plainTextBytes.Length];
        byte[] tag = new byte[TagSize];

        using var aesGcm = new AesGcm(key, TagSize);
        aesGcm.Encrypt(nonce, plainTextBytes, ciphertext, tag);

        return (ciphertext, nonce, tag);
    }

    public byte[] Decrypt(byte[] ciphertext, byte[] nonce, byte[] tag, byte[] key)
    {
        byte[] plainTextBytes = new byte[ciphertext.Length];

        using var aesGcm = new AesGcm(key, TagSize);
        aesGcm.Decrypt(nonce, ciphertext, tag, plainTextBytes);

        return plainTextBytes;
    }
}