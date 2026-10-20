using System;
using System.Security.Cryptography;
using System.Text;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PassowrdVault.Services;

namespace PassowrdVault.ViewModels;

public partial class MainViewModel : ViewModelBase
{
    private const string VerificationToken = "VAULT_MASTER_KEY_VERIFIED";
    private readonly CryptoService _crypto = new();
    private readonly VaultRepository _repo = new("vault.db");

    [ObservableProperty]
    private string _masterPassword = string.Empty;

    [ObservableProperty]
    private string _statusMessage = string.Empty;

    [ObservableProperty]
    private bool _isUnlocked;

    public MainViewModel()
    {
        _repo.InitializeDatabase();
    }

    [RelayCommand]
    private void Unlock()
    {
        if (string.IsNullOrWhiteSpace(MasterPassword))
        {
            StatusMessage = "Zadej master heslo!";
            return;
        }

        try
        {
            // První spuštění – vytvoření nového trezoru
            if (!HasMasterKeySet())
            {
                SetupNewMasterKey(MasterPassword);
                StatusMessage = "Trezor vytvořen a odemčen!";
                IsUnlocked = true;
                return;
            }

            // Odemčení existujícího trezoru
            var meta = _repo.GetMasterMeta();
            byte[] keyCandidate = _crypto.DeriveKey(MasterPassword, meta.Salt);
            byte[] decryptedTokenBytes = _crypto.Decrypt(meta.Ciphertext, meta.Nonce, meta.Tag, keyCandidate);

            if (Encoding.UTF8.GetString(decryptedTokenBytes) == VerificationToken)
            {
                StatusMessage = "Trezor odemčen!";
                IsUnlocked = true;
            }
            else
            {
                StatusMessage = "Špatné master heslo!";
            }
        }
        catch (CryptographicException)
        {
            StatusMessage = "Špatné master heslo!";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Chyba: {ex.Message}";
        }
    }

    private bool HasMasterKeySet()
    {
        try
        {
            _repo.GetMasterMeta();
            return true;
        }
        catch
        {
            return false;
        }
    }

    private void SetupNewMasterKey(string password)
    {
        byte[] salt = _crypto.GenerateSalt();
        byte[] masterKey = _crypto.DeriveKey(password, salt);
        byte[] tokenBytes = Encoding.UTF8.GetBytes(VerificationToken);

        var (vCipher, vNonce, vTag) = _crypto.Encrypt(tokenBytes, masterKey);
        _repo.SaveMasterKeyVerification(salt, vCipher, vNonce, vTag);
    }
}