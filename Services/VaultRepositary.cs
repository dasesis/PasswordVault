using System;
using Microsoft.Data.Sqlite;

namespace PassowrdVault.Services;

public class VaultRepository
{
    private readonly string _dbPath;

    public VaultRepository(string dbPath = "vault.db")
    {
        _dbPath = dbPath;
    }

    public void InitializeDatabase()
    {
        using var connection = new SqliteConnection($"Data Source={_dbPath}");
        connection.Open();

        using var commandMeta = connection.CreateCommand();
        commandMeta.CommandText = @"
            CREATE TABLE IF NOT EXISTS meta (
                id INTEGER PRIMARY KEY AUTOINCREMENT, 
                salt BLOB NOT NULL, 
                verification_ciphertext BLOB NOT NULL, 
                verification_nonce BLOB NOT NULL, 
                verification_tag BLOB NOT NULL
            );";
        commandMeta.ExecuteNonQuery();

        using var commandEntries = connection.CreateCommand();
        commandEntries.CommandText = @"
            CREATE TABLE IF NOT EXISTS entries (
                id TEXT PRIMARY KEY, 
                title TEXT NOT NULL, 
                payload BLOB NOT NULL, 
                nonce BLOB NOT NULL, 
                tag BLOB NOT NULL
            );";
        commandEntries.ExecuteNonQuery();
    }

    public void SaveMasterKeyVerification(byte[] salt, byte[] ciphertext, byte[] nonce, byte[] tag)
    {
        using var connection = new SqliteConnection($"Data Source={_dbPath}");
        connection.Open();

        using var command = connection.CreateCommand();
        command.CommandText = "INSERT INTO meta (salt, verification_ciphertext, verification_nonce, verification_tag) VALUES (@salt, @ciphertext, @nonce, @tag);";
        command.Parameters.AddWithValue("@salt", salt);
        command.Parameters.AddWithValue("@ciphertext", ciphertext);
        command.Parameters.AddWithValue("@nonce", nonce);
        command.Parameters.AddWithValue("@tag", tag);
        command.ExecuteNonQuery();
    }

    public (byte[] Salt, byte[] Ciphertext, byte[] Nonce, byte[] Tag) GetMasterMeta()
    {
        using var connection = new SqliteConnection($"Data Source={_dbPath}");
        connection.Open();

        using var command = connection.CreateCommand();
        command.CommandText = "SELECT salt, verification_ciphertext, verification_nonce, verification_tag FROM meta LIMIT 1;";
        using var reader = command.ExecuteReader();
        if (reader.Read())
        {
            return (
                (byte[])reader["salt"],
                (byte[])reader["verification_ciphertext"],
                (byte[])reader["verification_nonce"],
                (byte[])reader["verification_tag"]
            );
        }
        throw new InvalidOperationException("Metadata trezoru nenalezena.");
    }
}