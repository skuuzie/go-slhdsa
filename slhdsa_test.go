package slhdsa_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	slhdsa "github.com/skuuzie/go-slhdsa"
	internal "github.com/skuuzie/go-slhdsa/internal"
)

var keyGenPassed, sigGenPassed, sigVerPassed bool

type TestFolderPath struct {
	KeyGen string
	SigGen string
	SigVer string
}

type ExpectedResult struct {
	VSID      int     `json:"vsId"`
	Algorithm *string `json:"algorithm"`
	Mode      *string `json:"mode"`
	Revision  *string `json:"revision"`
	IsSample  *bool   `json:"isSample"`

	TestGroups []struct {
		TGID int `json:"tgId"`

		TestCases []struct {
			TCID int `json:"tcId"`

			// KeyGen
			PrivateKey *string `json:"sk"`
			PublicKey  *string `json:"pk"`

			// SigGen
			Signature *string `json:"signature"`

			// SigVer
			IsVerified *bool `json:"testPassed"`
		} `json:"tests"`
	} `json:"testGroups"`
}

type Prompt struct {
	VSID      int     `json:"vsId"`
	Algorithm *string `json:"algorithm"`
	Mode      *string `json:"mode"`
	Revision  *string `json:"revision"`
	IsSample  *bool   `json:"isSample"`

	TestGroups []struct {
		TGID         int    `json:"tgId"`
		Type         string `json:"testType"`
		ParameterSet string `json:"parameterSet"`

		// SigGen
		IsDeterministic *bool `json:"deterministic"`

		// SigGen & SigVer
		SignatureInterface *string `json:"signatureInterface"`
		PreHash            *string `json:"preHash"`

		Tests []struct {
			TCID int `json:"tcId"`

			// KeyGen
			SKSeed *string `json:"skSeed"`
			SKPRF  *string `json:"skPrf"`
			PKSeed *string `json:"pkSeed"`

			// SigGen
			PrivateKey *string `json:"sk"`
			Randomness *string `json:"additionalRandomness"`

			// SigVer
			PublicKey *string `json:"pk"`
			Signature *string `json:"signature"`

			// SigGen & SigVer
			Message       *string `json:"message"`
			ContextString *string `json:"context"`
			HashAlgorithm *string `json:"hashAlg"`
		} `json:"tests"`
	} `json:"testGroups"`
}

func getTestFolderPath() TestFolderPath {
	return TestFolderPath{
		KeyGen: "test-case/SLH-DSA-keyGen-FIPS205/",
		SigGen: "test-case/SLH-DSA-sigGen-FIPS205/",
		SigVer: "test-case/SLH-DSA-sigVer-FIPS205/",
	}
}

func loadJSON(filePath string, v interface{}) error {
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	decoder := json.NewDecoder(f)
	return decoder.Decode(v)
}

func runTestSuite(t *testing.T, testPath string, testFunc func(*testing.T, Prompt, ExpectedResult)) {
	var expectedResults ExpectedResult
	var prompts Prompt

	if err := loadJSON(testPath+"expectedResults.json", &expectedResults); err != nil {
		t.Error(err)
	}

	if err := loadJSON(testPath+"prompt.json", &prompts); err != nil {
		t.Error(err)
	}

	fmt.Printf("\nSTART %s\n", *prompts.Mode)
	testFunc(t, prompts, expectedResults)
	fmt.Printf("END %s\n", *prompts.Mode)
}

func TestKeyGen(t *testing.T) {
	keyGenPassed = false
	tPath := getTestFolderPath()

	runTestSuite(t, tPath.KeyGen, func(t *testing.T, prompts Prompt, expectedResults ExpectedResult) {
		for i := range prompts.TestGroups {
			tgPrompt := prompts.TestGroups[i]
			tgExpected := expectedResults.TestGroups[i]

			fmt.Printf("%v | Test Group %v\n", tgPrompt.ParameterSet, tgPrompt.TGID)
			ctx, err := internal.NewSlhDsa(tgPrompt.ParameterSet)

			if err != nil {
				t.Error(err)
			}

			for j := range tgPrompt.Tests {
				p := tgPrompt.Tests[j]
				e := tgExpected.TestCases[j]

				skSeed, _ := hex.DecodeString(*p.SKSeed)
				skPrf, _ := hex.DecodeString(*p.SKPRF)
				pkSeed, _ := hex.DecodeString(*p.PKSeed)
				expectedSk, _ := hex.DecodeString(*e.PrivateKey)
				expectedPk, _ := hex.DecodeString(*e.PublicKey)

				sk, pk := ctx.SlhKeygenInternal(skSeed, skPrf, pkSeed)

				if !bytes.Equal(sk.KeyBytes, expectedSk) {
					t.Errorf("[FAIL Private Key] Expected: %v | Got: %v", expectedSk, sk.KeyBytes)
					t.FailNow()
				}

				if !bytes.Equal(pk.KeyBytes, expectedPk) {
					t.Errorf("[FAIL Public Key] Expected: %v | Got: %v", expectedPk, pk.KeyBytes)
					t.FailNow()
				}

				fmt.Printf("Test Case %v OK\n", p.TCID)
			}
		}
	})

	keyGenPassed = true
}

func TestSigGen(t *testing.T) {
	sigGenPassed = false
	tPath := getTestFolderPath()

	runTestSuite(t, tPath.SigGen, func(t *testing.T, prompts Prompt, expectedResults ExpectedResult) {
		for i := range prompts.TestGroups {
			tgPrompt := prompts.TestGroups[i]
			tgExpected := expectedResults.TestGroups[i]

			fmt.Printf("Test Group %v | %v %v\n", tgPrompt.TGID, tgPrompt.ParameterSet, *tgPrompt.SignatureInterface)
			ctx, err := internal.NewSlhDsa(tgPrompt.ParameterSet)

			if err != nil {
				t.Error(err)
			}

			for j := range tgPrompt.Tests {
				var randomness []byte
				var context []byte
				alg := slhdsa.PreHashAlgorithm.Pure

				p := tgPrompt.Tests[j]
				e := tgExpected.TestCases[j]

				if !*tgPrompt.IsDeterministic {
					randomness, _ = hex.DecodeString(*p.Randomness)
				} else {
					randomness = nil
				}

				_sk, _ := hex.DecodeString(*p.PrivateKey)
				sk, _ := ctx.GetPrivateKeyFromBytes(_sk)
				msg, _ := hex.DecodeString(*p.Message)
				expectedSig, _ := hex.DecodeString(*e.Signature)

				if p.ContextString != nil {
					if len(*p.ContextString) != 0 {
						context, _ = hex.DecodeString(*p.ContextString)
					} else {
						context = nil
					}
				}

				var sig []byte
				if *tgPrompt.SignatureInterface == "external" {
					var mp []byte
					if *tgPrompt.PreHash == "preHash" {
						alg = *p.HashAlgorithm
					}
					alg := internal.PreHashAlgorithmMap[alg]
					if alg != internal.Pure {
						mp = internal.PreHash(alg, msg, context)
					} else {
						mp = append(append(internal.ToByte(0, 1), append(internal.ToByte(len(context), 1), context...)...), msg...)
					}
					_sig := ctx.SlhSignInternal(mp, sk, randomness)
					sig, _ = _sig.Deserialize(*ctx)
				} else {
					_sig := ctx.SlhSignInternal(msg, sk, randomness)
					sig, _ = _sig.Deserialize(*ctx)
				}

				if !bytes.Equal(sig, expectedSig) {
					t.Errorf("[TC %v FAIL %v %v] Expected: %v | Got: %v", p.TCID, alg, tgPrompt.ParameterSet, expectedSig[:32], sig[:32])
					t.FailNow()
				} else {
					fmt.Printf("Test Case %v OK\n", p.TCID)
				}
			}
		}
	})

	sigGenPassed = true
}

func TestSigVer(t *testing.T) {
	sigVerPassed = false
	tPath := getTestFolderPath()

	runTestSuite(t, tPath.SigVer, func(t *testing.T, prompts Prompt, expectedResults ExpectedResult) {
		for i := range prompts.TestGroups {
			tgPrompt := prompts.TestGroups[i]
			tgExpected := expectedResults.TestGroups[i]

			fmt.Printf("Test Group %v | %v %v\n", tgPrompt.TGID, tgPrompt.ParameterSet, *tgPrompt.SignatureInterface)
			ctx, err := internal.NewSlhDsa(tgPrompt.ParameterSet)

			if err != nil {
				t.Error(err)
			}

			for j := range tgPrompt.Tests {
				var context []byte
				alg := slhdsa.PreHashAlgorithm.Pure

				p := tgPrompt.Tests[j]
				e := tgExpected.TestCases[j]

				_pk, _ := hex.DecodeString(*p.PublicKey)
				pk, _ := ctx.GetPublicKeyFromBytes(_pk)
				msg, _ := hex.DecodeString(*p.Message)
				sig, _ := hex.DecodeString(*p.Signature)
				actual := e.IsVerified

				if p.ContextString != nil {
					if len(*p.ContextString) != 0 {
						context, _ = hex.DecodeString(*p.ContextString)
					} else {
						context = nil
					}
				}

				var verified bool
				if *tgPrompt.SignatureInterface == "external" {
					if *tgPrompt.PreHash == "preHash" {
						alg = *p.HashAlgorithm
					}
					verified, _ = ctx.VerifySignature(pk, msg, sig, context, alg)
				} else {
					_sig, err := internal.SerializeToSig(*ctx, sig)
					if err != nil {
						verified = false
					} else {
						verified = ctx.SlhVerifyInternal(msg, _sig, pk)
					}
				}

				if verified != *actual {
					t.Errorf("[TC %v FAIL %v %v] Expected: %v | Got: %v", p.TCID, alg, tgPrompt.ParameterSet, *actual, verified)
					t.FailNow()
				} else {
					fmt.Printf("Test Case %v OK\n", p.TCID)
				}
			}
		}
	})

	sigVerPassed = true
}
