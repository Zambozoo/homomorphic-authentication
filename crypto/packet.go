package crypto

import (
	"sync"

	"github.com/thedonutfactory/go-tfhe/core"
	"github.com/thedonutfactory/go-tfhe/gates"
	"github.com/thedonutfactory/go-tfhe/types"
)

// Packet is used to encrypt values, and decrypt or operate on encrypted values
type Packet struct {
	pub *gates.PublicKey
	prv *gates.PrivateKey
}

// lweKeyGen is a wrapper around a go-tfhe function to use ByteStream
func lweKeyGen(byteStream *ByteStream, result *core.LweKey) {
	z := make([]int32, result.Params.N)
	for i := range z {
		z[i] = types.Torus32(byteStream.NextByte() & 1)
	}
	result.Key = z
}

// tlweKeyGen is a wrapper around a go-tfhe function to use ByteStream
func tlweKeyGen(byteStream *ByteStream, result *core.TLweKey) {
	N := result.Params.N
	k := result.Params.K
	for i := int32(0); i < k; i++ {
		for j := int32(0); j < N; j++ {
			result.Key[i].Coefs[j] = types.Torus32(byteStream.NextByte() & 1)
		}
	}
}

// generateKeys is a wrapper around go-tfhe functions to generate a public-private key pair from a ByteStream
func generateKeys(byteStream *ByteStream, params *gates.GateBootstrappingParameterSet) (*gates.PublicKey, *gates.PrivateKey) {
	lweKey := core.NewLweKey(params.InOutParams)
	lweKeyGen(byteStream, lweKey)

	tgswKey := core.NewTGswKey(params.TgswParams)
	tlweKeyGen(byteStream, &tgswKey.TlweKey)

	bkw := core.NewLweBootstrappingKeyWrapper(params.KsT, params.KsBasebit, params.InOutParams, params.TgswParams, lweKey, tgswKey)

	return gates.NewPublicKey(params, bkw), gates.NewPrivateKey(params, bkw, lweKey, tgswKey)
}

// MakePacket makes a Packet from a ByteStream
func MakePacket(byteStream *ByteStream) *Packet {
	ctx := gates.DefaultGateBootstrappingParameters(128)
	pub, prv := generateKeys(byteStream, ctx)
	return &Packet{
		pub: pub,
		prv: prv,
	}
}

// MakePublicPacket makes a Packet from a public key to operate on encrypted values
func MakePublicPacket(publicKey *PublicKey) *Packet {
	return &Packet{pub: publicKey.fromPublicKey()}
}

// Pub returns a Packet's public key
func (p *Packet) Pub() *gates.PublicKey {
	return p.pub
}

// Pub returns a Packet's private key
func (p *Packet) Prv() *gates.PrivateKey {
	return p.prv
}

// Encrypt uses a Packet's private key to encrypt a payload
func (p *Packet) Encrypt(payload []byte) gates.Ctxt {
	ctxt := make(gates.Ctxt, 8*len(payload))
	i := 0
	for _, b := range payload {
		for j := 0; j < 8; j++ {
			ctxt[i] = p.prv.BootsSymEncrypt(int(b>>j) & 0x1)
			i++
		}
	}

	return ctxt
}

// Decrypt uses a Packet's private key to decrypt a payload
func (p *Packet) Decrypt(encryptedPayload gates.Ctxt) []byte {
	result := make([]byte, (len(encryptedPayload)+7)/8)
	if len(result) == 0 {
		return nil
	}

	i := 0
	for j := 0; ; j++ {
		for k := 0; k < 8; k++ {
			result[j] = (result[j] >> 1) | (byte(p.prv.BootsSymDecrypt(encryptedPayload[i])) << 7)
			i++

			if i >= len(encryptedPayload) {
				return result
			}
		}
	}
}

// And uses a Packet's public key to perform a bitwise And on two encrypted payloads in parallel
func (p *Packet) And(a, b gates.Ctxt) gates.Ctxt {
	return p.ParallelBinary((*gates.PublicKey).And)(a, b)
}

// Or uses a Packet's public key to perform a bitwise Or on two encrypted payloads in parallel
func (p *Packet) Or(a, b gates.Ctxt) gates.Ctxt {
	return p.ParallelBinary((*gates.PublicKey).Or)(a, b)
}

// Xor uses a Packet's public key to perform a bitwise Xor on two encrypted payloads in parallel
func (p *Packet) Xor(a, b gates.Ctxt) gates.Ctxt {
	return p.ParallelBinary((*gates.PublicKey).Xor)(a, b)
}

// XNor uses a Packet's public key to perform a bitwise XNor on two encrypted payloads in parallel
func (p *Packet) XNor(a, b gates.Ctxt) gates.Ctxt {
	return p.ParallelBinary((*gates.PublicKey).Xnor)(a, b)
}

// Not uses a Packet's public key to perform a bitwise Not on two encrypted payloads in parallel
func (p *Packet) Not(a gates.Ctxt) gates.Ctxt {
	return p.ParallelUnary((*gates.PublicKey).Not)(a)
}

// Copy uses a Packet's public key to copy an encrypted payload in parallel
func (p *Packet) Copy(a gates.Ctxt) gates.Ctxt {
	return p.ParallelUnary((*gates.PublicKey).Copy)(a)
}

// ParallelUnary uses a Packet's public key to performa binary operation on an encrypted payload in parallel
func (p *Packet) ParallelUnary(operation func(pk *gates.PublicKey, a *core.LweSample) *core.LweSample) func(a gates.Ctxt) gates.Ctxt {
	return func(a gates.Ctxt) gates.Ctxt {
		var wg sync.WaitGroup
		wg.Add(len(a))

		result := make([]*core.LweSample, len(a))
		for i := range a {
			i := i
			go func() {
				defer wg.Done()

				result[i] = operation(p.pub, a[i])
			}()
		}

		wg.Wait()
		return result
	}
}

// ParallelBinary uses a Packet's public key to performa binary operation on two encrypted payloads in parallel
func (p *Packet) ParallelBinary(operation func(pk *gates.PublicKey, a, b *core.LweSample) *core.LweSample) func(a, b gates.Ctxt) gates.Ctxt {
	return func(a, b gates.Ctxt) gates.Ctxt {
		if len(a) != len(b) {
			panic("expected equal bit size")
		}

		var wg sync.WaitGroup
		wg.Add(len(a))

		result := make([]*core.LweSample, len(a))
		for i := range a {
			i := i
			go func() {
				defer wg.Done()

				result[i] = operation(p.pub, a[i], b[i])
			}()
		}

		wg.Wait()
		return result
	}
}
