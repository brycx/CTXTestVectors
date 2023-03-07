using System.Text;
using CTXTestVectors;
using Newtonsoft.Json;
using NSec.Cryptography;


CreateCtxXChaCha20Poly1305Balek2b();

void CreateCtxXChaCha20Poly1305Balek2b()
{
    var mutator = Blake2b.Blake2b_256;

    Span<byte> key = stackalloc byte[32];
    Span<byte> nonce = stackalloc byte[32];
    ReadOnlySpan<byte> msg = Encoding.UTF8.GetBytes("Hello, world!");
    ReadOnlySpan<byte> ad = Encoding.UTF8.GetBytes("Additional data");


    // Empty/non-empty AD
    // Empty/non-empty Msg
    // Failures: wrong key, wrong nonce, wrong ad, wrong msg, wrong ciphertext, wrong AeadTag,
    // wrong tag.
    var testVectors = new List<TestVector>();
    
    key = mutator.Hash(key);
    nonce = mutator.Hash(nonce).AsSpan()[..24];
    testVectors.Add(XChaCha20Poly1305Blake2B256.Encrypt("", key, nonce, ad, msg));
    
    
    key = mutator.Hash(key);
    nonce = mutator.Hash(nonce).AsSpan()[..24];
    testVectors.Add(XChaCha20Poly1305Blake2B256.Encrypt("empty AD", key, nonce, Array.Empty<byte>(), msg));
    
    key = mutator.Hash(key);
    nonce = mutator.Hash(nonce).AsSpan()[..24];
    testVectors.Add(XChaCha20Poly1305Blake2B256.Encrypt("empty Msg", key, nonce, ad, Array.Empty<byte>()));

    
    key = mutator.Hash(key);
    nonce = mutator.Hash(nonce).AsSpan()[..24];
    testVectors.Add(XChaCha20Poly1305Blake2B256.Encrypt("empty AD+Msg", key, nonce, Array.Empty<byte>(), Array.Empty<byte>()));
    
    key = mutator.Hash(key);
    nonce = mutator.Hash(nonce).AsSpan()[..24];
    var tv = XChaCha20Poly1305Blake2B256.Encrypt("wrong key", key, nonce, ad, msg);
    tv.Key = Convert.ToHexString(new byte[32]);
    tv.Result = "false";
    testVectors.Add(tv);
    
    key = mutator.Hash(key);
    nonce = mutator.Hash(nonce).AsSpan()[..24];
    tv = XChaCha20Poly1305Blake2B256.Encrypt("wrong nonce", key, nonce, ad, msg);
    tv.Nonce = Convert.ToHexString(new byte[24]);
    tv.Result = "false";
    testVectors.Add(tv);
    
    key = mutator.Hash(key);
    nonce = mutator.Hash(nonce).AsSpan()[..24];
    tv = XChaCha20Poly1305Blake2B256.Encrypt("wrong AD", key, nonce, ad, msg);
    var adFlip = ad.ToArray();
    adFlip[0] ^= 1;
    tv.Ad = Convert.ToHexString(adFlip);
    tv.Result = "false";
    testVectors.Add(tv);
    
    key = mutator.Hash(key);
    nonce = mutator.Hash(nonce).AsSpan()[..24];
    tv = XChaCha20Poly1305Blake2B256.Encrypt("wrong msg", key, nonce, ad, msg);
    var msgFlip = msg.ToArray();
    msgFlip[0] ^= 1;
    tv.Msg = Convert.ToHexString(msgFlip);
    tv.Result = "false";
    testVectors.Add(tv);

    key = mutator.Hash(key);
    nonce = mutator.Hash(nonce).AsSpan()[..24];
    tv = XChaCha20Poly1305Blake2B256.Encrypt("wrong ciphertext", key, nonce, ad, msg);
    var ctFlip = Convert.FromHexString(tv.Ciphertext);
    ctFlip[0] ^= 1;
    tv.Ciphertext = Convert.ToHexString(ctFlip);
    tv.Result = "false";
    testVectors.Add(tv);
    
    key = mutator.Hash(key);
    nonce = mutator.Hash(nonce).AsSpan()[..24];
    tv = XChaCha20Poly1305Blake2B256.Encrypt("wrong AeadTag", key, nonce, ad, msg);
    var aeadTagFlip = Convert.FromHexString(tv.AeadTag);
    aeadTagFlip[0] ^= 1;
    tv.AeadTag = Convert.ToHexString(aeadTagFlip);
    tv.Result = "false";
    testVectors.Add(tv);
    
    key = mutator.Hash(key);
    nonce = mutator.Hash(nonce).AsSpan()[..24];
    tv = XChaCha20Poly1305Blake2B256.Encrypt("wrong Tag", key, nonce, ad, msg);
    var tagFlip = Convert.FromHexString(tv.Tag);
    tagFlip[0] ^= 1;
    tv.Tag = Convert.ToHexString(tagFlip);
    tv.Result = "false";
    testVectors.Add(tv);

    var testFile = JsonConvert.SerializeObject(testVectors, Formatting.Indented);
    File.AppendAllText("../../../TestFiles/ctx_xchacha20_poly1305_blake2b_256.json", testFile);
}