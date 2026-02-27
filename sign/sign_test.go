package sign

import (
	"fmt"
	"testing"
)

func TestGenerateMacSha256Key(t *testing.T) {
	key, err := GenerateHmacSha256Key()
	if err != nil {
		t.Fatalf("GenerateHmacSha256Key() returned an error: %v", err)
	}
	if key == "" {
		t.Errorf("Expected non-empty key, got empty string")
	}
	fmt.Println("Generated HMAC-SHA256 Key:", key)
}

func TestSignAndVerify(t *testing.T) {
	key, err := GenerateHmacSha256Key()
	if err != nil {
		t.Fatalf("GenerateHmacSha256Key() returned an error: %v", err)
	}
	data := "Hello, Ceramicraft!"
	signature := GenHmacSha256([]byte(key), data)

	if signature == "" {
		t.Errorf("Expected non-empty signature, got empty string")
	}
	fmt.Println("Singn: ", signature)

	valid := VerifyHmacSha256([]byte(key), data, signature)
	if !valid {
		t.Errorf("Expected signature to be valid, but it was not")
	}

	invalid := VerifyHmacSha256([]byte(key), data, "invalidsignature")
	if invalid {
		t.Errorf("Expected signature to be invalid, but it was valid")
	}
}
