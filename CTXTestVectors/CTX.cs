using NSec.Cryptography;

namespace CTXTestVectors;

/// <summary>
/// Committing XChaCha20-Poly1305 with BLAKE2b256: "On Committing Authenticated Encryption", Chan and Rogaway, 2022.
///
/// Note that there is one deviation from the paper: We store T (Poly1305 tag), alongside T*.
/// This is because NSec doesn't provide access to raw Poly1305 functionality, which we'd need to reconstruct original
/// T during decryption. This is not available from Microsoft either.
///
/// </summary>
public static class XChaCha20Poly1305Blake2B256
{

    public static TestVector Encrypt(string comment, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ad, ReadOnlySpan<byte> input)
    {
        IncrementalHash.Initialize(HashAlgorithm.Blake2b_256, out var hashCtx);
        IncrementalHash.Update(ref hashCtx, key); // H(K)
        IncrementalHash.Update(ref hashCtx, nonce); // H(N)
        IncrementalHash.Update(ref hashCtx, ad); // H(A)
        
        using var sk = Key.Import(AeadAlgorithm.XChaCha20Poly1305, key, KeyBlobFormat.RawSymmetricKey);
        var ct = AeadAlgorithm.XChaCha20Poly1305.Encrypt(sk, nonce, ad, input);
        IncrementalHash.Update(ref hashCtx, ct.AsSpan()[input.Length..]); // H(T)
        var altTag = IncrementalHash.Finalize(ref hashCtx);

        var tv = new TestVector()
        {
            Key = Convert.ToHexString(key),
            Nonce = Convert.ToHexString(nonce),
            Ad = Convert.ToHexString(ad),
            Msg = Convert.ToHexString(input),
            Ciphertext = Convert.ToHexString(ct.AsSpan()[..input.Length]),
            AeadTag = Convert.ToHexString(ct.AsSpan()[input.Length..]),
            Tag = Convert.ToHexString(altTag),
            Result = "true",
            Comment = comment,
        };

        return tv;
    }
}


