package mmr

import (
	"testing"
)

func TestGeneratePQCKeys(t *testing.T) {
	pub, priv, err := GeneratePQCKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(pub) == 0 || len(priv) == 0 {
		t.Error("expected non-empty keys")
	}
}

func TestSignVerifyPQC(t *testing.T) {
	pub, priv, err := GeneratePQCKeys()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("audit log entry")
	sig, err := SignPQC(priv, msg)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPQC(pub, msg, sig) {
		t.Error("VerifyPQC failed")
	}
	if VerifyPQC(pub, []byte("wrong"), sig) {
		t.Error("VerifyPQC should fail for wrong message")
	}
}
