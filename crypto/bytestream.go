package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"hash/fnv"
	"math/rand"
)

// ByteStream is used to generate a stream of bytes
type ByteStream struct {
	stream cipher.Stream
}

// MakeByteStream returns a ByteStream initialized by key
func MakeByteStream(key []byte) *ByteStream {
	seed1Hash := fnv.New128()
	seed1Hash.Write(append(key, 0))
	seed1 := seed1Hash.Sum(nil)

	seed2Hash := fnv.New128()
	seed2Hash.Write(append(key, 1))
	seed2 := seed2Hash.Sum(nil)

	block, err := aes.NewCipher(seed1)
	if err != nil {
		panic(err)
	}

	return &ByteStream{stream: cipher.NewCTR(block, seed2)}
}

// MakeRandByteStream returns a ByteStream initialized by a random value
func MakeRandByteStream() *ByteStream {
	return MakeByteStream(binary.LittleEndian.AppendUint64(nil, rand.Uint64()))
}

// NextBytes returns a ByteStream's next n bytes
func (cbs *ByteStream) NextBytes(n int) []byte {
	value := make([]byte, n)
	cbs.stream.XORKeyStream(value, value)
	return value
}

// NextByte returns a ByteStream's next byte
func (cbs *ByteStream) NextByte() byte {
	return cbs.NextBytes(1)[0]
}
