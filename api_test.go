package ceramicraftsecure

import (
	"errors"
	"testing"

	"github.com/sw5005-sus/ceramicraft-secure/vault"
	"go.uber.org/mock/gomock"
)

func TestEncryptDecrypt(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockKeyManager := vault.NewMockIKeyManager(ctrl)
	keyManager = mockKeyManager
	aesKey := "5a4ecfdc57425512529825ba42aa5a6fd95fcd46321c0ebcfcbc6ed880b6ef83"
	mockKeyManager.EXPECT().GetLatestVersion().Return(1).AnyTimes()
	mockKeyManager.EXPECT().GetSecConfigByKey(aesKeyName, 1).Return(aesKey, nil).AnyTimes()
	plainText := "Hello, Ceramicraft!"
	cipherText, err := AesEncrypt(plainText)
	if err != nil {
		t.Fatalf("AesEncrypt() returned an error: %v", err)
	}
	if cipherText == "" {
		t.Errorf("Expected non-empty cipher text, got empty string")
	}
	decryptedText, err := AesDecrypt(cipherText)
	if err != nil {
		t.Fatalf("AesDecrypt() returned an error: %v", err)
	}
	if decryptedText != plainText {
		t.Errorf("Decrypted text does not match original. Got: %s, want: %s", decryptedText, plainText)
	}
}

func TestEncDecError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockKeyManager := vault.NewMockIKeyManager(ctrl)
	keyManager = mockKeyManager
	mockKeyManager.EXPECT().GetLatestVersion().Return(1).AnyTimes()
	mockKeyManager.EXPECT().GetSecConfigByKey(aesKeyName, 1).Return("", nil).AnyTimes()
	_, err := AesEncrypt("Test data")
	if err == nil {
		t.Errorf("Expected error due to missing AES key, got nil")
	}
	_, err = AesDecrypt("v1.invalidciphertext")
	if err == nil {
		t.Errorf("Expected error due to invalid ciphertext format, got nil")
	}
}

func TestSignAndVerify(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockKeyManager := vault.NewMockIKeyManager(ctrl)
	keyManager = mockKeyManager
	signKey := "dd3a34701855b0df392e2c66d75837e2ca0d0697b324ea1ad120d91d419f0591"
	mockKeyManager.EXPECT().GetLatestVersion().Return(1).AnyTimes()
	mockKeyManager.EXPECT().GetSecConfigByKey(hmacKeyName, 1).Return(signKey, nil).Times(2)
	data := "Important data to sign"
	signature, err := GenHmacSha256(data)
	if err != nil {
		t.Fatalf("GenHmacSha256() returned an error: %v", err)
	}
	if signature == "" {
		t.Errorf("Expected non-empty signature, got empty string")
	}
	valid, err := VerifyHmacSha256(data, signature)
	if err != nil {
		t.Fatalf("VerifyHmacSha256() returned an error: %v", err)
	}
	if !valid {
		t.Errorf("Expected signature to be valid, got invalid")
	}
	mockKeyManager.EXPECT().GetSecConfigByKey(hmacKeyName, 1).Return("", nil).Times(2)
	_, err = GenHmacSha256(data)
	if err == nil {
		t.Fatalf("Expected error due to missing HMAC key, got nil")
	}
	_, err = VerifyHmacSha256(data, signature)
	if err == nil {
		t.Fatalf("Expected error due to missing HMAC key, got nil")
	}
}

func TestSignVerifyError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockKeyManager := vault.NewMockIKeyManager(ctrl)
	keyManager = mockKeyManager
	mockKeyManager.EXPECT().GetLatestVersion().Return(1).AnyTimes()
	mockKeyManager.EXPECT().GetSecConfigByKey(hmacKeyName, 1).Return("", errors.New("key get fail")).AnyTimes()
	_, err := GenHmacSha256("Test data")
	if err == nil {
		t.Errorf("Expected error due to missing HMAC key, got nil")
	}
	_, err = VerifyHmacSha256("Test data", "v1.validsignature")
	if err == nil {
		t.Errorf("Expected error due to missing HMAC key, got nil")
	}
}
