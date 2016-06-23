// 
// Copyright © Microsoft Corporation, All Rights Reserved
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
// ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
// PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
//
// See the Apache License, Version 2.0 for the specific language
// governing permissions and limitations under the License.

using System;
using System.Collections.Generic;
using System.Configuration;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Hyak.Common;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.WebKey;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace HelloKeyVault
{
    internal class Program
    {
        private static KeyVaultClient _keyVaultClient;
        private static InputValidator _inputValidator;
        private static ClientCredential _clientCredential;

        private static void Main(string[] args)
        {
            KeyBundle keyBundle = null; // The key specification and attributes
            Secret secret = null;
            var keyName = string.Empty;
            var secretName = string.Empty;

            _inputValidator = new InputValidator(args);

            TracingAdapter.AddTracingInterceptor(new ConsoleTracingInterceptor());
            TracingAdapter.IsEnabled = _inputValidator.GetTracingEnabled();

            var clientId = ConfigurationManager.AppSettings["AuthClientId"];
            var clientSecret = ConfigurationManager.AppSettings["AuthClientSecret"];
            _clientCredential = new ClientCredential(clientId, clientSecret);

            _keyVaultClient = new KeyVaultClient(GetAccessToken, GetHttpClient());

            // SECURITY: DO NOT USE IN PRODUCTION CODE; FOR TEST PURPOSES ONLY
            //ServicePointManager.ServerCertificateValidationCallback += ( sender, cert, chain, sslPolicyErrors ) => true;

            var successfulOperations = new List<KeyOperationType>();
            var failedOperations = new List<KeyOperationType>();

            foreach (var operation in _inputValidator.GetKeyOperations())
            {
                try
                {
                    Console.Out.WriteLine("\n\n {0} is in process ...", operation);
                    switch (operation)
                    {
                        case KeyOperationType.CREATE_KEY:
                            keyBundle = CreateKey(keyBundle, out keyName);
                            break;

                        case KeyOperationType.IMPORT_KEY:
                            keyBundle = ImportKey(out keyName);
                            break;

                        case KeyOperationType.GET_KEY:
                            keyBundle = GetKey(keyBundle);
                            break;

                        case KeyOperationType.LIST_KEYVERSIONS:
                            ListKeyVersions(keyName);
                            break;

                        case KeyOperationType.UPDATE_KEY:
                            keyBundle = UpdateKey(keyName);
                            break;

                        case KeyOperationType.DELETE_KEY:
                            DeleteKey(keyName);
                            break;

                        case KeyOperationType.BACKUP_RESTORE:
                            keyBundle = BackupRestoreKey(keyName);
                            break;

                        case KeyOperationType.SIGN_VERIFY:
                            SignVerify(keyBundle);
                            break;

                        case KeyOperationType.ENCRYPT_DECRYPT:
                            EncryptDecrypt(keyBundle);
                            break;

                        case KeyOperationType.ENCRYPT:
                            Encrypt(keyBundle);
                            break;

                        case KeyOperationType.DECRYPT:
                            Decrypt(keyBundle);
                            break;

                        case KeyOperationType.WRAP_UNWRAP:
                            WrapUnwrap(keyBundle);
                            break;

                        case KeyOperationType.CREATE_SECRET:
                            secret = CreateSecret(out secretName);
                            break;

                        case KeyOperationType.GET_SECRET:
                            secret = GetSecret(secret.Id);
                            break;

                        case KeyOperationType.LIST_SECRETS:
                            ListSecrets();
                            break;

                        case KeyOperationType.DELETE_SECRET:
                            secret = DeleteSecret(secretName);
                            break;
                    }
                    successfulOperations.Add(operation);
                }
                catch (KeyVaultClientException exception)
                {
                    // The Key Vault exceptions are logged but not thrown to avoid blocking execution for other commands running in batch
                    Console.Out.WriteLine("Operation failed: {0}", exception.Message);
                    failedOperations.Add(operation);
                }
            }

            Console.Out.WriteLine("\n\n---------------Successful Key Vault operations:---------------");
            foreach (var type in successfulOperations)
                Console.Out.WriteLine("\t{0}", type);

            if (failedOperations.Count > 0)
            {
                Console.Out.WriteLine("\n\n---------------Failed Key Vault operations:---------------");
                foreach (var type in failedOperations)
                    Console.Out.WriteLine("\t{0}", type);
            }

            Console.Out.WriteLine();
            Console.Out.Write("Press enter to continue . . .");
            Console.In.Read();
        }

        /// <summary>
        ///     Updates key attributes
        /// </summary>
        /// <param name="keyName"> a global key identifier of the key to update </param>
        /// <returns> updated key bundle </returns>
        private static KeyBundle UpdateKey(string keyName)
        {
            var vaultAddress = _inputValidator.GetVaultAddress();
            keyName = (keyName == string.Empty) ? _inputValidator.GetKeyId() : keyName;

            // Get key attribute to update
            var keyAttributes = _inputValidator.GetUpdateKeyAttribute();
            var updatedKey =
                _keyVaultClient.UpdateKeyAsync(vaultAddress, keyName, attributes: keyAttributes)
                    .GetAwaiter()
                    .GetResult();

            Console.Out.WriteLine("Updated key:---------------");
            PrintoutKey(updatedKey);

            return updatedKey;
        }

        /// <summary>
        ///     Import an asymmetric key into the vault
        /// </summary>
        /// <param name="keyName">Key name</param>
        /// <returns> imported key bundle</returns>
        private static KeyBundle ImportKey(out string keyName)
        {
            var vaultAddress = _inputValidator.GetVaultAddress();
            keyName = _inputValidator.GetKeyName();
            var isHsm = _inputValidator.GetKeyType() == JsonWebKeyType.RsaHsm;

            // Get key bundle which is needed for importing a key
            var keyBundle = _inputValidator.GetImportKeyBundle();
            var importedKey =
                _keyVaultClient.ImportKeyAsync(vaultAddress, keyName, keyBundle, isHsm).GetAwaiter().GetResult();

            Console.Out.WriteLine("Imported key:---------------");
            PrintoutKey(importedKey);

            return importedKey;
        }

        /// <summary>
        ///     Gets the specified key
        /// </summary>
        /// <param name="key"> a global key identifier of the key to get </param>
        /// <returns> retrieved key bundle </returns>
        private static KeyBundle GetKey(KeyBundle key)
        {
            KeyBundle retrievedKey;
            var keyVersion = _inputValidator.GetKeyVersion();
            var keyName = _inputValidator.GetKeyName(allowDefault: false);

            if (keyVersion != string.Empty || keyName != string.Empty)
            {
                var vaultAddress = _inputValidator.GetVaultAddress();
                if (keyVersion != string.Empty)
                {
                    keyName = _inputValidator.GetKeyName(true);
                    retrievedKey =
                        _keyVaultClient.GetKeyAsync(vaultAddress, keyName, keyVersion).GetAwaiter().GetResult();
                }
                else
                {
                    retrievedKey = _keyVaultClient.GetKeyAsync(vaultAddress, keyName).GetAwaiter().GetResult();
                }
            }
            else
            {
                // If the key is not initialized get the key id from args
                var keyId = (key != null) ? key.Key.Kid : _inputValidator.GetKeyId();

                // Get the key using its ID
                retrievedKey = _keyVaultClient.GetKeyAsync(keyId).GetAwaiter().GetResult();
            }

            Console.Out.WriteLine("Retrived key:---------------");
            PrintoutKey(retrievedKey);

            //store the created key for the next operation if we have a sequence of operations
            return retrievedKey;
        }

        /// <summary>
        ///     List the versions of a key
        /// </summary>
        /// <param name="keyName"> key name</param>
        private static void ListKeyVersions(string keyName)
        {
            var vaultAddress = _inputValidator.GetVaultAddress();
            keyName = (keyName == string.Empty) ? _inputValidator.GetKeyId() : keyName;

            var numKeyVersions = 0;
            const int maxResults = 1;

            Console.Out.WriteLine("List key versions:---------------");

            var results =
                _keyVaultClient.GetKeyVersionsAsync(vaultAddress, keyName, maxResults).GetAwaiter().GetResult();

            if (results != null && results.Value != null)
            {
                numKeyVersions += results.Value.Count();
                foreach (var m in results.Value)
                    Console.Out.WriteLine("\t{0}-{1}", m.Identifier.Name, m.Identifier.Version);
            }

            while (results != null && !string.IsNullOrWhiteSpace(results.NextLink))
            {
                results = _keyVaultClient.GetKeyVersionsNextAsync(results.NextLink).GetAwaiter().GetResult();
                if (results != null && results.Value != null)
                {
                    numKeyVersions += results.Value.Count();
                    foreach (var m in results.Value)
                        Console.Out.WriteLine("\t{0}-{1}", m.Identifier.Name, m.Identifier.Version);
                }
            }

            Console.Out.WriteLine("\n\tNumber of versions of key {0} in the vault: {1}", keyName, numKeyVersions);
        }

        /// <summary>
        ///     Created the specified key
        /// </summary>
        /// <param name="keyBundle"> key bundle to create </param>
        /// <param name="keyName">name of the key</param>
        /// <returns> created key bundle </returns>
        private static KeyBundle CreateKey(KeyBundle keyBundle, out string keyName)
        {
            // Get key bundle which is needed for creating a key
            keyBundle = keyBundle ?? _inputValidator.GetKeyBundle();
            var vaultAddress = _inputValidator.GetVaultAddress();
            keyName = _inputValidator.GetKeyName();

            var tags = _inputValidator.GetTags();

            // Create key in the KeyVault key vault
            var createdKey =
                _keyVaultClient.CreateKeyAsync(vaultAddress, keyName, keyBundle.Key.Kty,
                    keyAttributes: keyBundle.Attributes, tags: tags).GetAwaiter().GetResult();

            Console.Out.WriteLine("Created key:---------------");
            PrintoutKey(createdKey);

            // Store the created key for the next operation if we have a sequence of operations
            return createdKey;
        }

        /// <summary>
        ///     Creates or updates a secret
        /// </summary>
        /// <returns> The created or the updated secret </returns>
        private static Secret CreateSecret(out string secretName)
        {
            secretName = _inputValidator.GetSecretName();
            var secretValue = _inputValidator.GetSecretValue();

            var tags = _inputValidator.GetTags();

            var contentType = _inputValidator.GetSecretContentType();

            var secret =
                _keyVaultClient.SetSecretAsync(_inputValidator.GetVaultAddress(), secretName, secretValue, tags,
                    contentType, _inputValidator.GetSecretAttributes()).GetAwaiter().GetResult();

            Console.Out.WriteLine("Created/Updated secret:---------------");
            PrintoutSecret(secret);

            return secret;
        }

        /// <summary>
        ///     Gets a secret
        /// </summary>
        /// <param name="secretId"> The secret ID </param>
        /// <returns> The created or the updated secret </returns>
        private static Secret GetSecret(string secretId)
        {
            Secret secret;
            var secretVersion = _inputValidator.GetSecretVersion();

            if (secretVersion != string.Empty)
            {
                var vaultAddress = _inputValidator.GetVaultAddress();
                var secretName = _inputValidator.GetSecretName(true);
                secret =
                    _keyVaultClient.GetSecretAsync(vaultAddress, secretName, secretVersion).GetAwaiter().GetResult();
            }
            else
            {
                secretId = secretId ?? _inputValidator.GetSecretId();
                secret = _keyVaultClient.GetSecretAsync(secretId).GetAwaiter().GetResult();
            }
            Console.Out.WriteLine("Retrieved secret:---------------");
            PrintoutSecret(secret);

            return secret;
        }

        /// <summary>
        ///     Lists secrets in a vault
        /// </summary>
        private static void ListSecrets()
        {
            var vaultAddress = _inputValidator.GetVaultAddress();
            var numSecretsInVault = 0;
            const int maxResults = 1;

            Console.Out.WriteLine("List secrets:---------------");
            var results = _keyVaultClient.GetSecretsAsync(vaultAddress, maxResults).GetAwaiter().GetResult();

            if (results != null && results.Value != null)
            {
                numSecretsInVault += results.Value.Count();
                foreach (var m in results.Value)
                    Console.Out.WriteLine("\t{0}", m.Identifier.Name);
            }

            while (results != null && !string.IsNullOrWhiteSpace(results.NextLink))
            {
                results = _keyVaultClient.GetSecretsNextAsync(results.NextLink).GetAwaiter().GetResult();
                if (results != null && results.Value != null)
                {
                    numSecretsInVault += results.Value.Count();
                    foreach (var m in results.Value)
                        Console.Out.WriteLine("\t{0}", m.Identifier.Name);
                }
            }

            Console.Out.WriteLine("\n\tNumber of secrets in the vault: {0}", numSecretsInVault);
        }

        /// <summary>
        ///     Deletes secret
        /// </summary>
        /// <param name="secretName"> The secret ID</param>
        /// <returns> The deleted secret </returns>
        private static Secret DeleteSecret(string secretName)
        {
            // If the secret is not initialized get the secret Id from args
            var vaultAddress = _inputValidator.GetVaultAddress();
            secretName = (secretName == string.Empty) ? _inputValidator.GetSecretName() : secretName;

            var secret = _keyVaultClient.DeleteSecretAsync(vaultAddress, secretName).GetAwaiter().GetResult();

            Console.Out.WriteLine("Deleted secret:---------------");
            PrintoutSecret(secret);

            return secret;
        }

        /// <summary>
        ///     backup the specified key and then restores the key into a vault
        /// </summary>
        /// <param name="keyName"> a global key identifier of the key to get </param>
        /// <returns> restored key bundle </returns>
        private static KeyBundle BackupRestoreKey(string keyName)
        {
            var vaultAddress = _inputValidator.GetVaultAddress();

            // Get a backup of the key and cache its backup value
            var backupKeyValue = _keyVaultClient.BackupKeyAsync(vaultAddress, keyName).GetAwaiter().GetResult();
            Console.Out.WriteLine(
                "The backup key value contains {0} bytes.\nTo restore it into a key vault this value should be provided!",
                backupKeyValue.Length);

            // Get the vault address from args or use the default one
            var newVaultAddress = _inputValidator.GetVaultAddress();

            // Delete any existing key in that vault.
            _keyVaultClient.DeleteKeyAsync(vaultAddress, keyName).GetAwaiter().GetResult();

            // Restore the backed up value into the vault
            var restoredKey = _keyVaultClient.RestoreKeyAsync(newVaultAddress, backupKeyValue).GetAwaiter().GetResult();

            Console.Out.WriteLine("Restored key:---------------");
            PrintoutKey(restoredKey);

            // Cache the restored key
            return restoredKey;
        }

        /// <summary>
        ///     Deletes the specified key
        /// </summary>
        /// <param name="keyName"> a global key identifier of the key to get </param>
        private static void DeleteKey(string keyName)
        {
            // If the key ID is not initialized get the key id from args
            var vaultAddress = _inputValidator.GetVaultAddress();
            keyName = (keyName == string.Empty) ? _inputValidator.GetKeyName() : keyName;

            // Delete the key with the specified ID
            var keyBundle = _keyVaultClient.DeleteKeyAsync(vaultAddress, keyName).GetAwaiter().GetResult();
            Console.Out.WriteLine("Key {0} is deleted successfully!", keyBundle.Key.Kid);
        }

        /// <summary>
        ///     Wraps a symmetric key and then unwrapps the wrapped key
        /// </summary>
        /// <param name="key"> a global key identifier of the key to get </param>
        private static void WrapUnwrap(KeyBundle key)
        {
            KeyOperationResult wrappedKey;

            var algorithm = _inputValidator.GetEncryptionAlgorithm();
            var symmetricKey = _inputValidator.GetSymmetricKey();

            var keyVersion = _inputValidator.GetKeyVersion();

            if (keyVersion != string.Empty)
            {
                var vaultAddress = _inputValidator.GetVaultAddress();
                var keyName = _inputValidator.GetKeyName(true);
                wrappedKey =
                    _keyVaultClient.WrapKeyAsync(vaultAddress, keyName, keyVersion, algorithm, symmetricKey)
                        .GetAwaiter()
                        .GetResult();
            }
            else
            {
                // If the key ID is not initialized get the key id from args
                var keyId = (key != null) ? key.Key.Kid : _inputValidator.GetKeyId();

                // Wrap the symmetric key
                wrappedKey = _keyVaultClient.WrapKeyAsync(keyId, algorithm, symmetricKey).GetAwaiter().GetResult();
            }

            Console.Out.WriteLine("The symmetric key is wrapped using key id {0} and algorithm {1}", wrappedKey.Kid,
                algorithm);

            // Unwrap the symmetric key
            var unwrappedKey =
                _keyVaultClient.UnwrapKeyAsync(wrappedKey.Kid, algorithm, wrappedKey.Result).GetAwaiter().GetResult();
            Console.Out.WriteLine("The unwrapped key is{0}the same as the original key!",
                symmetricKey.SequenceEqual(unwrappedKey.Result) ? " " : " not ");
        }

        /// <summary>
        ///     Encrypts a plain text and then decrypts the encrypted text
        /// </summary>
        /// <param name="key"> key to use for the encryption & decryption operations </param>
        private static void EncryptDecrypt(KeyBundle key)
        {
            var algorithm = _inputValidator.GetEncryptionAlgorithm();
            var plainText = _inputValidator.GetPlainText();

            var keyVersion = _inputValidator.GetKeyVersion();

            var operationResult = _encrypt(key, keyVersion, algorithm, plainText);

            Console.Out.WriteLine("The text is encrypted using key id {0} and algorithm {1}", operationResult.Kid,
                algorithm);

            // Decrypt the encrypted data
            var decryptedText =
                _keyVaultClient.DecryptAsync(operationResult.Kid, algorithm, operationResult.Result)
                    .GetAwaiter()
                    .GetResult();

            Console.Out.WriteLine("The decrypted text is{0}the same as the original key!",
                plainText.SequenceEqual(decryptedText.Result) ? " " : " not ");
            Console.Out.WriteLine("The decrypted text is: {0}", Encoding.UTF8.GetString(decryptedText.Result));
        }

        private static KeyOperationResult _encrypt(KeyBundle key, string keyVersion, string algorithm, byte[] plainText)
        {
            KeyOperationResult operationResult;

            if (keyVersion != string.Empty)
            {
                var vaultAddress = _inputValidator.GetVaultAddress();
                var keyName = _inputValidator.GetKeyName(true);

                // Encrypt the input data using the specified algorithm
                operationResult =
                    _keyVaultClient.EncryptAsync(vaultAddress, keyName, keyVersion, algorithm, plainText)
                        .GetAwaiter()
                        .GetResult();
            }
            else
            {
                // If the key is not initialized get the key id from args
                var keyId = (key != null) ? key.Key.Kid : _inputValidator.GetKeyId();
                // Encrypt the input data using the specified algorithm
                operationResult = _keyVaultClient.EncryptAsync(keyId, algorithm, plainText).GetAwaiter().GetResult();
            }

            return operationResult;
        }

        /// <summary>
        ///     Encrypts plaintext
        /// </summary>
        /// <param name="key"> key to use for the encryption </param>
        private static void Encrypt(KeyBundle key)
        {
            var algorithm = _inputValidator.GetEncryptionAlgorithm();
            var plainText = _inputValidator.GetPlainText();

            var keyVersion = _inputValidator.GetKeyVersion();

            var operationResult = _encrypt(key, keyVersion, algorithm, plainText);

            File.WriteAllText("cipherText.txt", Convert.ToBase64String(operationResult.Result));

            Console.Out.WriteLine("The text is encrypted using key id {0} and algorithm {1}", operationResult.Kid,
                algorithm);
            Console.Out.WriteLine("Encrypted text, base-64 encoded: {0}", Convert.ToBase64String(operationResult.Result));
        }

        /// <summary>
        ///     Decrypts cipherText
        /// </summary>
        /// <param name="key"> key to use for the decryption </param>
        private static void Decrypt(KeyBundle key)
        {
            var algorithm = _inputValidator.GetEncryptionAlgorithm();
            var cipherText = _inputValidator.GetCipherText();

            var localKey = (key ?? GetKey(null));

            // Decrypt the encrypted data
            var operationResult =
                _keyVaultClient.DecryptAsync(localKey.KeyIdentifier.ToString(), algorithm, cipherText)
                    .GetAwaiter()
                    .GetResult();

            Console.Out.WriteLine("The decrypted text is: {0}", Encoding.UTF8.GetString(operationResult.Result));
        }

        /// <summary>
        ///     Signs a hash and then verifies the signature
        /// </summary>
        /// <param name="key"> a global key identifier of the key to get </param>
        private static void SignVerify(KeyBundle key)
        {
            KeyOperationResult signature;
            var algorithm = _inputValidator.GetSignAlgorithm();
            var digest = _inputValidator.GetDigestHash();

            var keyVersion = _inputValidator.GetKeyVersion();
            if (keyVersion != string.Empty)
            {
                var vaultAddress = _inputValidator.GetVaultAddress();
                var keyName = _inputValidator.GetKeyName(true);
                signature =
                    _keyVaultClient.SignAsync(vaultAddress, keyName, keyVersion, algorithm, digest)
                        .GetAwaiter()
                        .GetResult();
            }
            else
            {
                // If the key is not initialized get the key id from args
                var keyId = (key != null) ? key.Key.Kid : _inputValidator.GetKeyId();

                // Create a signature
                signature = _keyVaultClient.SignAsync(keyId, algorithm, digest).GetAwaiter().GetResult();
            }
            Console.Out.WriteLine("The signature is created using key id {0} and algorithm {1} ", signature.Kid,
                algorithm);

            // Verify the signature
            var isVerified =
                _keyVaultClient.VerifyAsync(signature.Kid, algorithm, digest, signature.Result).GetAwaiter().GetResult();
            Console.Out.WriteLine("The signature is {0} verified!", isVerified ? "" : "not ");
        }

        /// <summary>
        ///     Prints out key bundle values
        /// </summary>
        /// <param name="keyBundle"> key bundle </param>
        private static void PrintoutKey(KeyBundle keyBundle)
        {
            Console.Out.WriteLine("Key: \n\tKey ID: {0}\n\tKey type: {1}",
                keyBundle.Key.Kid, keyBundle.Key.Kty);

            var expiryDateStr = keyBundle.Attributes.Expires.HasValue
                ? keyBundle.Attributes.Expires.ToString()
                : "Never";

            var notBeforeStr = keyBundle.Attributes.NotBefore.HasValue
                ? keyBundle.Attributes.NotBefore.ToString()
                : UnixEpoch.EpochDate.ToString(CultureInfo.InvariantCulture);

            Console.Out.WriteLine("Key attributes: \n\tIs the key enabled: {0}\n\tExpiry date: {1}\n\tEnable date: {2}",
                keyBundle.Attributes.Enabled, expiryDateStr, notBeforeStr);
        }

        /// <summary>
        ///     Prints out secret values
        /// </summary>
        /// <param name="secret"> secret </param>
        private static void PrintoutSecret(Secret secret)
        {
            Console.Out.WriteLine("\n\tSecret ID: {0}\n\tSecret Value: {1}",
                secret.Id, secret.Value);

            var expiryDateStr = secret.Attributes.Expires.HasValue
                ? secret.Attributes.Expires.ToString()
                : "Never";

            var notBeforeStr = secret.Attributes.NotBefore.HasValue
                ? secret.Attributes.NotBefore.ToString()
                : UnixEpoch.EpochDate.ToString(CultureInfo.InvariantCulture);

            Console.Out.WriteLine(
                "Secret attributes: \n\tIs the key enabled: {0}\n\tExpiry date: {1}\n\tEnable date: {2}\n\tContent type: {3}",
                secret.Attributes.Enabled, expiryDateStr, notBeforeStr, secret.ContentType);

            PrintoutTags(secret.Tags);
        }

        /// <summary>
        ///     Prints out the tags for a key/secret
        /// </summary>
        /// <param name="tags"></param>
        private static void PrintoutTags(Dictionary<string, string> tags)
        {
            if (tags != null)
            {
                Console.Out.Write("\tTags: ");
                foreach (var key in tags.Keys)
                {
                    Console.Out.Write("\n\t\t{0} : {1}", key, tags[key]);
                }
                Console.WriteLine();
            }
        }

        /// <summary>
        ///     Gets the access token
        /// </summary>
        /// <param name="authority"> Authority </param>
        /// <param name="resource"> Resource </param>
        /// <param name="scope"> scope </param>
        /// <returns> token </returns>
        public static async Task<string> GetAccessToken(string authority, string resource, string scope)
        {
            var context = new AuthenticationContext(authority, TokenCache.DefaultShared);
            var result = await context.AcquireTokenAsync(resource, _clientCredential);

            return result.AccessToken;
        }

        /// <summary>
        ///     Create an HttpClient object that optionally includes logic to override the HOST header
        ///     field for advanced testing purposes.
        /// </summary>
        /// <returns>HttpClient instance to use for Key Vault service communication</returns>
        private static HttpClient GetHttpClient()
        {
            return (HttpClientFactory.Create(new InjectHostHeaderHttpMessageHandler()));
        }
    }
}