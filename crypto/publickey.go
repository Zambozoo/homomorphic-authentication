package crypto

import (
	"encoding/json"

	"github.com/thedonutfactory/go-tfhe/core"
	"github.com/thedonutfactory/go-tfhe/fft"
	"github.com/thedonutfactory/go-tfhe/gates"
)

type (
	// lweBootstrappingKeyWrapper is a json marshallable wrapper around a go-tfhe primitive
	lweBootstrappingKeyWrapper struct {
		Bk    *core.LweBootstrappingKey
		BkFFT *lweBootstrappingKeyFFT
	}

	// lweBootstrappingKeyFFT is a json version of a go-tfhe primitive
	lweBootstrappingKeyFFT struct {
		InOutParams   *core.LweParams
		BkParams      *core.TGswParams
		AccumParams   *core.TLweParams
		ExtractParams *core.LweParams
		Bk            []*tGswSampleFFT
		Ks            *core.LweKeySwitchKey
	}

	// tGswSampleFFT is a json marshallable version of a go-tfhe primitive
	tGswSampleFFT struct {
		AllSample  []*tLweSampleFFT
		BlocSample [][]*tLweSampleFFT
		K          int32
		L          int32
	}

	// tLweSampleFFT is a json marshallable wrapper version of a go-tfhe primitive
	tLweSampleFFT struct {
		A               []*lagrangeHalfCPolynomial
		CurrentVariance float64
		K               int32
	}

	// lagrangeHalfCPolynomial is a json marshallable wrapper  version of a go-tfhe primitive
	lagrangeHalfCPolynomial struct {
		Coefs []complex128
	}

	// _lagrangeHalfCPolynomial is a json marshallable version of a go-tfhe primitive
	_lagrangeHalfCPolynomial struct {
		Coefs []_complex128
	}

	// _complex128 is a json marshallable version of complex128
	_complex128 struct {
		Re float64
		Im float64
	}

	// PublicKey is a json marshallable version of the go-tfhe public key
	PublicKey struct {
		Params *gates.GateBootstrappingParameterSet
		Bkw    *lweBootstrappingKeyWrapper
	}
)

func (lhcp *lagrangeHalfCPolynomial) MarshalJSON() ([]byte, error) {
	coefs := make([]_complex128, len(lhcp.Coefs))
	for i, c := range lhcp.Coefs {
		coefs[i] = _complex128{
			Re: real(c),
			Im: imag(c),
		}
	}
	l := _lagrangeHalfCPolynomial{Coefs: coefs}

	return json.Marshal(&l)
}

func (lhcp *lagrangeHalfCPolynomial) UnmarshalJSON(data []byte) error {
	var l _lagrangeHalfCPolynomial
	if err := json.Unmarshal(data, &l); err != nil {
		return err
	}

	lhcp.Coefs = make([]complex128, len(l.Coefs))
	for i, c := range l.Coefs {
		lhcp.Coefs[i] = complex(c.Re, c.Im)
	}

	return nil
}

// MakePublicKey returns a PublicKey from a go-tfhe PublicKey
func MakePublicKey(pk *gates.PublicKey) *PublicKey {
	Bk := make([]*tGswSampleFFT, len(pk.Bkw.BkFFT.Bk))
	for i, v := range pk.Bkw.BkFFT.Bk {
		AllSample := make([]*tLweSampleFFT, len(v.AllSample))
		for j, w := range v.AllSample {
			A := make([]*lagrangeHalfCPolynomial, len(w.A))
			for k, x := range w.A {
				A[k] = &lagrangeHalfCPolynomial{
					Coefs: x.Coefs,
				}
			}

			AllSample[j] = &tLweSampleFFT{
				A:               A,
				CurrentVariance: w.CurrentVariance,
				K:               w.K,
			}
		}

		BlocSample := make([][]*tLweSampleFFT, len(v.BlocSample))
		for j, w := range v.BlocSample {
			BlocSample[j] = make([]*tLweSampleFFT, len(w))
			for k, x := range w {
				A := make([]*lagrangeHalfCPolynomial, len(x.A))
				for k, y := range x.A {
					A[k] = &lagrangeHalfCPolynomial{
						Coefs: y.Coefs,
					}
				}

				BlocSample[j][k] = &tLweSampleFFT{
					A:               A,
					CurrentVariance: x.CurrentVariance,
					K:               x.K,
				}
			}
		}
		Bk[i] = &tGswSampleFFT{
			AllSample:  AllSample,
			BlocSample: BlocSample,
			K:          v.K,
			L:          v.L,
		}
	}

	BkFFT := &lweBootstrappingKeyFFT{
		InOutParams:   pk.Bkw.Bk.InOutParams,
		BkParams:      pk.Bkw.Bk.BkParams,
		AccumParams:   pk.Bkw.Bk.AccumParams,
		ExtractParams: pk.Bkw.Bk.ExtractParams,
		Ks:            pk.Bkw.Bk.Ks,
		Bk:            Bk,
	}
	Bkw := &lweBootstrappingKeyWrapper{
		Bk:    pk.Bkw.Bk,
		BkFFT: BkFFT,
	}

	return &PublicKey{
		Params: pk.Params,
		Bkw:    Bkw,
	}
}

// fromPublicKey returns a go-tfhe PublicKey from a PublicKey
func (pk *PublicKey) fromPublicKey() *gates.PublicKey {
	Bk := make([]*core.TGswSampleFFT, len(pk.Bkw.BkFFT.Bk))
	for i, v := range pk.Bkw.BkFFT.Bk {
		AllSample := make([]*core.TLweSampleFFT, len(v.AllSample))
		for j, w := range v.AllSample {
			A := make([]*fft.LagrangeHalfCPolynomial, len(w.A))
			for k, x := range w.A {
				A[k] = &fft.LagrangeHalfCPolynomial{
					Coefs: x.Coefs,
				}
			}

			AllSample[j] = &core.TLweSampleFFT{
				A:               A,
				CurrentVariance: w.CurrentVariance,
				K:               w.K,
			}
		}

		BlocSample := make([][]*core.TLweSampleFFT, len(v.BlocSample))
		for j, w := range v.BlocSample {
			BlocSample[j] = make([]*core.TLweSampleFFT, len(w))
			for k, x := range w {
				A := make([]*fft.LagrangeHalfCPolynomial, len(x.A))
				for k, y := range x.A {
					A[k] = &fft.LagrangeHalfCPolynomial{
						Coefs: y.Coefs,
					}
				}

				BlocSample[j][k] = &core.TLweSampleFFT{
					A:               A,
					CurrentVariance: x.CurrentVariance,
					K:               x.K,
				}
			}
		}
		Bk[i] = &core.TGswSampleFFT{
			AllSample:  AllSample,
			BlocSample: BlocSample,
			K:          v.K,
			L:          v.L,
		}
	}

	BkFFT := &core.LweBootstrappingKeyFFT{
		InOutParams:   pk.Bkw.Bk.InOutParams,
		BkParams:      pk.Bkw.Bk.BkParams,
		AccumParams:   pk.Bkw.Bk.AccumParams,
		ExtractParams: pk.Bkw.Bk.ExtractParams,
		Ks:            pk.Bkw.Bk.Ks,
		Bk:            Bk,
	}
	Bkw := &core.LweBootstrappingKeyWrapper{
		Bk:    pk.Bkw.Bk,
		BkFFT: BkFFT,
	}

	return &gates.PublicKey{
		Params: pk.Params,
		Bkw:    Bkw,
	}
}
