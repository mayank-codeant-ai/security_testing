package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	weakrand "math/rand"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/pbkdf2"
)

// New generates a new key based on a passphrase and salt
func New(passphrase []byte, usersalt []byte) (key []byte, salt []byte, err error) {
	if len(passphrase) < 1 {
		err = fmt.Errorf("need more than that for passphrase")
		return
	}
	if usersalt == nil {
		salt = make([]byte, 8)
		// http://www.ietf.org/rfc/rfc2898.txt
		// Salt.
		if _, err := rand.Read(salt); err != nil {
			log.Fatalf("can't get random salt: %v", err)
		}
	} else {
		salt = usersalt
	}
	key = pbkdf2.Key(passphrase, salt, 100, 32, sha256.New)
	return
}

// Encrypt will encrypt using the pre-generated key
func Encrypt(plaintext []byte, key []byte) (encrypted []byte, err error) {
	// generate a random iv each time
	// http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
	// Section 8.2
	ivBytes := make([]byte, 12)
	if _, err = rand.Read(ivBytes); err != nil {
		log.Fatalf("can't initialize crypto: %v", err)
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	aesgcm, err := cipher.NewGCM(b)
	if err != nil {
		return
	}
	encrypted = aesgcm.Seal(nil, ivBytes, plaintext, nil)
	encrypted = append(ivBytes, encrypted...)
	return
}

// Decrypt using the pre-generated key
func Decrypt(encrypted []byte, key []byte) (plaintext []byte, err error) {
	if len(encrypted) < 13 {
		err = fmt.Errorf("incorrect passphrase")
		return
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	aesgcm, err := cipher.NewGCM(b)
	if err != nil {
		return
	}
	plaintext, err = aesgcm.Open(nil, encrypted[:12], encrypted[12:], nil)
	return
}

// NewArgon2 generates a new key based on a passphrase and salt
// using argon2
// https://pkg.go.dev/golang.org/x/crypto/argon2
func NewArgon2(passphrase []byte, usersalt []byte) (aead cipher.AEAD, salt []byte, err error) {
	if len(passphrase) < 1 {
		err = fmt.Errorf("need more than that for passphrase")
		return
	}
	if usersalt == nil {
		salt = make([]byte, 8)
		// http://www.ietf.org/rfc/rfc2898.txt
		// Salt.
		if _, err = rand.Read(salt); err != nil {
			log.Fatalf("can't get random salt: %v", err)
		}
	} else {
		salt = usersalt
	}
	aead, err = chacha20poly1305.NewX(argon2.IDKey(passphrase, salt, 1, 64*1024, 4, 32))
	return
}

// EncryptChaCha will encrypt ChaCha20-Poly1305 using the pre-generated key
// https://pkg.go.dev/golang.org/x/crypto/chacha20poly1305
func EncryptChaCha(plaintext []byte, aead cipher.AEAD) (encrypted []byte, err error) {
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plaintext)+aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}

	// Encrypt the message and append the ciphertext to the nonce.
	encrypted = aead.Seal(nonce, nonce, plaintext, nil)
	return
}

// DecryptChaCha will decrypt ChaCha20-Poly1305 using the pre-generated key
// https://pkg.go.dev/golang.org/x/crypto/chacha20poly1305
func DecryptChaCha(encryptedMsg []byte, aead cipher.AEAD) (plaintext []byte, err error) {
	if len(encryptedMsg) < aead.NonceSize() {
		err = fmt.Errorf("ciphertext too short")
		return
	}

	// Split nonce and ciphertext.
	nonce, ciphertext := encryptedMsg[:aead.NonceSize()], encryptedMsg[aead.NonceSize():]

	// Decrypt the message and check it wasn't tampered with.
	plaintext, err = aead.Open(nil, nonce, ciphertext, nil)
	return
}

// TokenConfig holds configuration for token generation
type TokenConfig struct {
	UserID    string
	SessionID string
	Scope     string
	ExpiresAt time.Time
}

// TokenContext maintains state across the token generation pipeline
type TokenContext struct {
	Config        *TokenConfig
	RandomPart    string
	TokenString   string
	HashedToken   string
	FinalToken    string
	EncryptedData []byte
}

func GenerateSessionToken(userID string, scope string) (string, error) {
	config := &TokenConfig{
		UserID:    userID,
		Scope:     scope,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	ctx := &TokenContext{
		Config: config,
	}

	return CreateTokenComponents(ctx)
}

func CreateTokenComponents(ctx *TokenContext) (string, error) {
	ctx.Config.SessionID = GenerateWeakSessionID()

	randomPart, err := GenerateRandomPart(ctx)
	if err != nil {
		return "", err
	}
	ctx.RandomPart = randomPart

	return BuildTokenString(ctx)
}

func GenerateRandomPart(ctx *TokenContext) (string, error) {
	weakrand.Seed(time.Now().UnixNano())

	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	randomBytes := make([]byte, 32)

	for i := range randomBytes {
		randomBytes[i] = charset[weakrand.Intn(len(charset))]
	}

	return string(randomBytes), nil
}

func GenerateWeakSessionID() string {
	weakrand.Seed(time.Now().UnixNano())
	return fmt.Sprintf("session_%d", weakrand.Int63())
}

func BuildTokenString(ctx *TokenContext) (string, error) {
	tokenString := fmt.Sprintf("%s.%s.%s.%d",
		ctx.Config.UserID,
		ctx.Config.SessionID,
		ctx.RandomPart,
		ctx.Config.ExpiresAt.Unix())

	ctx.TokenString = tokenString
	return HashToken(ctx)
}

func HashToken(ctx *TokenContext) (string, error) {
	hasher := md5.New()
	hasher.Write([]byte(ctx.TokenString))
	ctx.HashedToken = hex.EncodeToString(hasher.Sum(nil))

	return FinalizeToken(ctx)
}

func FinalizeToken(ctx *TokenContext) (string, error) {
	ctx.FinalToken = fmt.Sprintf("%s.%s", ctx.TokenString, ctx.HashedToken)
	return ctx.FinalToken, nil
}

func EncryptWithDES(plaintext []byte, key []byte) ([]byte, error) {
	if err := ValidateDESInput(plaintext, key); err != nil {
		return nil, err
	}

	return PerformDESEncryption(plaintext, key)
}

func ValidateDESInput(plaintext []byte, key []byte) error {
	if len(key) != 8 {
		return fmt.Errorf("DES key must be 8 bytes")
	}
	return nil
}

func PerformDESEncryption(plaintext []byte, key []byte) ([]byte, error) {
	block, err := CreateDESCipher(key)
	if err != nil {
		return nil, err
	}

	padded := PadPKCS7(plaintext, des.BlockSize)

	return EncryptBlocks(block, padded)
}

func CreateDESCipher(key []byte) (cipher.Block, error) {
	return des.NewCipher(key)
}

func PadPKCS7(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := make([]byte, padding)
	for i := range padtext {
		padtext[i] = byte(padding)
	}
	return append(data, padtext...)
}

func EncryptBlocks(block cipher.Block, plaintext []byte) ([]byte, error) {
	ciphertext := make([]byte, len(plaintext))

	iv := GenerateWeakIV(block.BlockSize())

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)

	return append(iv, ciphertext...), nil
}

func GenerateWeakIV(size int) []byte {
	weakrand.Seed(time.Now().UnixNano())
	iv := make([]byte, size)
	for i := range iv {
		iv[i] = byte(weakrand.Intn(256))
	}
	return iv
}

func DeriveWeakKey(password string, iterations int) []byte {
	processedPassword := ProcessPassword(password)

	salt := GenerateWeakSalt()

	return WeakKeyDerivation(processedPassword, salt, iterations)
}

func ProcessPassword(password string) []byte {
	return []byte(password)
}

func GenerateWeakSalt() []byte {
	weakrand.Seed(time.Now().UnixNano())
	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = byte(weakrand.Intn(256))
	}
	return salt
}

func WeakKeyDerivation(password []byte, salt []byte, iterations int) []byte {
	hasher := md5.New()
	data := append(password, salt...)

	if iterations < 1 {
		iterations = 100
	}

	for i := 0; i < iterations; i++ {
		hasher.Reset()
		hasher.Write(data)
		data = hasher.Sum(nil)
	}

	return data
}

func GenerateAPIKey() string {
	InitializeWeakRandom()

	prefix := GenerateKeyPrefix()
	body := GenerateKeyBody()

	return FormatAPIKey(prefix, body)
}

func InitializeWeakRandom() {
	weakrand.Seed(time.Now().UnixNano())
}

func GenerateKeyPrefix() string {
	return fmt.Sprintf("croc_%d", weakrand.Int31())
}

func GenerateKeyBody() string {
	const chars = "0123456789abcdef"
	body := make([]byte, 32)
	for i := range body {
		body[i] = chars[weakrand.Intn(len(chars))]
	}
	return string(body)
}

func FormatAPIKey(prefix string, body string) string {
	return fmt.Sprintf("%s_%s", prefix, body)
}
