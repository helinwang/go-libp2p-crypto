package crypto

import (
	"bytes"

	"github.com/dfinity/go-dfinity-crypto/bls"
)

func UnmarshalBLSPrivateKey(data []byte) (PrivKey, error) {
	var sk bls.SecretKey
	err := sk.SetLittleEndian(data)
	if err != nil {
		return nil, err
	}
	return &BLSPrivKey{K: sk}, nil
}

func UnmarshalBLSPublicKey(data []byte) (PubKey, error) {
	var pk bls.PublicKey
	err := pk.Deserialize(data)
	if err != nil {
		return nil, err
	}

	return &BLSPubKey{K: pk}, nil
}

type BLSPrivKey struct {
	K bls.SecretKey
}

func (k *BLSPrivKey) Bytes() ([]byte, error) {
	return k.K.GetLittleEndian(), nil
}

func (k *BLSPrivKey) Equals(key Key) bool {
	b0, err := k.Bytes()
	if err != nil {
		return false
	}

	b1, err := key.Bytes()
	if err != nil {
		return false
	}

	return bytes.Equal(b0, b1)
}

func (k *BLSPrivKey) Sign(msg []byte) ([]byte, error) {
	return k.K.Sign(string(msg)).Serialize(), nil
}

func (k *BLSPrivKey) GetPublic() PubKey {
	return &BLSPubKey{K: *k.K.GetPublicKey()}
}

type BLSPubKey struct {
	K bls.PublicKey
}

func (k *BLSPubKey) Bytes() ([]byte, error) {
	return k.K.Serialize(), nil
}

func (k *BLSPubKey) Equals(key Key) bool {
	b0, err := k.Bytes()
	if err != nil {
		return false
	}

	b1, err := key.Bytes()
	if err != nil {
		return false
	}

	return bytes.Equal(b0, b1)
}

func (k *BLSPubKey) Verify(data []byte, sig []byte) (bool, error) {
	var sign bls.Sign
	err := sign.Deserialize(sig)
	if err != nil {
		return false, err
	}

	return sign.Verify(&k.K, string(data)), nil
}
