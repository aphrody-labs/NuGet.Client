// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace NuGet.Common
{
    /// <summary>
    /// Aphrody shared content-addressed store (APHRODY_STORE), same layout as aphrody-pkg-store and the
    /// aphrody-labs/vcpkg-tool fork: blobs/sha256/&lt;2&gt;/&lt;hex&gt; is the blob, blobs/sha512/&lt;2&gt;/&lt;hex&gt; a hard link to it.
    /// NuGet places global-packages in nuget/packages and the http cache in nuget/http-cache.
    /// </summary>
    public static class AphrodyStore
    {
        public const string EnvironmentKey = "APHRODY_STORE";

        public static string? GetRoot()
        {
            var root = Environment.GetEnvironmentVariable(EnvironmentKey);
            if (string.IsNullOrEmpty(root) || root == "0" || string.Equals(root, "off", StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }

            return Path.IsPathRooted(root) ? Path.GetFullPath(root) : null;
        }

        public static string BlobPath(string root, string algorithm, string hexDigest)
        {
            var hex = hexDigest.ToLowerInvariant();
            return Path.Combine(root, "blobs", algorithm, hex.Substring(0, 2), hex);
        }

        /// <summary>
        /// Moves <paramref name="file"/> into the store (or drops it when the content is already there) and puts a hard
        /// link back at its path. <paramref name="sha512Base64"/> is the NuGet package hash when known.
        /// Returns false and leaves the file untouched when the store is disabled or the move fails.
        /// </summary>
        public static bool TryIngest(string file, string? sha512Base64)
        {
            var root = GetRoot();
            if (root == null || !File.Exists(file))
            {
                return false;
            }

            try
            {
                var sha512 = sha512Base64 != null ? ToHex(Convert.FromBase64String(sha512Base64)) : HashFile(file, SHA512.Create());
                var alias = BlobPath(root, "sha512", sha512);
                if (!File.Exists(alias))
                {
                    var blob = BlobPath(root, "sha256", HashFile(file, SHA256.Create()));
                    Directory.CreateDirectory(Path.GetDirectoryName(blob)!);
                    Directory.CreateDirectory(Path.GetDirectoryName(alias)!);
                    if (!File.Exists(blob))
                    {
                        var staging = blob + "." + Path.GetRandomFileName();
                        File.Copy(file, staging);
                        try
                        {
                            File.Move(staging, blob);
                        }
                        catch (IOException) when (File.Exists(blob))
                        {
                            File.Delete(staging);
                        }
                    }

                    if (!CreateHardLink(blob, alias) && !File.Exists(alias))
                    {
                        File.Copy(blob, alias);
                    }
                }

                return Materialize(alias, file);
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is FormatException)
            {
                return false;
            }
        }

        /// <summary>Replaces <paramref name="destination"/> with a hard link to <paramref name="source"/>.</summary>
        public static bool Materialize(string source, string destination)
        {
            var staging = destination + "." + Path.GetRandomFileName();
            if (!CreateHardLink(source, staging))
            {
                return false;
            }

            try
            {
                File.Delete(destination);
                File.Move(staging, destination);
                return true;
            }
            catch (IOException)
            {
                File.Delete(staging);
                return false;
            }
        }

        private static bool CreateHardLink(string existing, string link)
        {
            if (RuntimeEnvironmentHelper.IsWindows)
            {
                return CreateHardLinkW(link, existing, IntPtr.Zero);
            }

            return SysLink(existing, link) == 0;
        }

        private static string HashFile(string file, HashAlgorithm algorithm)
        {
            using (algorithm)
            using (var stream = File.OpenRead(file))
            {
                return ToHex(algorithm.ComputeHash(stream));
            }
        }

        private static string ToHex(byte[] bytes)
        {
            var chars = new char[bytes.Length * 2];
            const string digits = "0123456789abcdef";
            for (var i = 0; i < bytes.Length; i++)
            {
                chars[i * 2] = digits[bytes[i] >> 4];
                chars[i * 2 + 1] = digits[bytes[i] & 0xF];
            }

            return new string(chars);
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateHardLinkW")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreateHardLinkW(string fileName, string existingFileName, IntPtr securityAttributes);

        [DllImport("libc", SetLastError = true, EntryPoint = "link")]
        private static extern int SysLink(string existing, string link);
    }
}
