package main

import (
	"encoding/base64"
	"fmt"
	"syscall/js"

	// "syscall/js"

	slhdsa "github.com/skuuzie/go-slhdsa"
)

func sigRegular() {
	ctx, _ := slhdsa.New(slhdsa.ParameterSet.SLHDSA_SHAKE_128s)

	sk, pk, _ := ctx.GenerateKeyPair()
	m := []byte("Test")
	sig, _ := ctx.GenerateSignature(sk, m, nil, false, slhdsa.PreHashAlgorithm.Pure)
	fmt.Println(ctx.VerifySignature(pk, m, sig, nil, slhdsa.PreHashAlgorithm.Pure))
}

func sigContext() {
	ctx, _ := slhdsa.New(slhdsa.ParameterSet.SLHDSA_SHAKE_128s)

	sk, pk, _ := ctx.GenerateKeyPair()
	m := []byte("Test")
	context := []byte("lalalala")
	sig, _ := ctx.GenerateSignature(sk, m, context, false, slhdsa.PreHashAlgorithm.Pure)
	fmt.Println(ctx.VerifySignature(pk, m, sig, context, slhdsa.PreHashAlgorithm.Pure))
}

func sigRandomness() {
	ctx, _ := slhdsa.New(slhdsa.ParameterSet.SLHDSA_SHAKE_128s)

	sk, pk, _ := ctx.GenerateKeyPair()
	m := []byte("Test")
	context := []byte("lalalala")
	sig, _ := ctx.GenerateSignature(sk, m, context, true, slhdsa.PreHashAlgorithm.Pure)
	fmt.Println(ctx.VerifySignature(pk, m, sig, context, slhdsa.PreHashAlgorithm.Pure))
}

func sigPrehash() {
	ctx, _ := slhdsa.New(slhdsa.ParameterSet.SLHDSA_SHAKE_128s)

	sk, pk, _ := ctx.GenerateKeyPair()
	m := []byte("Test")
	context := []byte("lalalala")
	sig, _ := ctx.GenerateSignature(sk, m, context, false, slhdsa.PreHashAlgorithm.SHA512_256)
	fmt.Println(ctx.VerifySignature(pk, m, sig, context, slhdsa.PreHashAlgorithm.SHA512_256))
}

func generateKeyPair(this js.Value, args []js.Value) interface{} {
	if len(args) != 1 {
		return map[string]interface{}{
			"error": "generateKeyPair requires exactly 1 argument (data)",
		}
	}

	fmt.Println(args[0].String())

	ctx, err := slhdsa.New(args[0].String())

	if err != nil {
		return map[string]interface{}{
			"error": err.Error(),
		}
	}

	sk, pk, err := ctx.GenerateKeyPair()

	if err != nil {
		return map[string]interface{}{
			"error": err.Error(),
		}
	}

	return map[string]interface{}{
		"privateKey": base64.RawStdEncoding.EncodeToString(sk.KeyBytes),
		"publicKey":  base64.RawStdEncoding.EncodeToString(pk.KeyBytes),
		"error":      nil,
	}
}

func getBoolFromWeb(val js.Value) (bool, error) {
	if val.Type() != js.TypeBoolean {
		return false, fmt.Errorf("expected boolean, got %s", val.Type().String())
	}

	return val.Bool(), nil
}

func getBytesFromWeb(val js.Value) ([]byte, error) {
	if val.Type() != js.TypeObject || !val.InstanceOf(js.Global().Get("Uint8Array")) {
		return nil, fmt.Errorf("expected Uint8Array, got %s", val.Type().String())
	}

	length := val.Get("byteLength").Int()
	buf := make([]byte, length)

	copied := js.CopyBytesToGo(buf, val)
	if copied != length {
		return nil, fmt.Errorf("incomplete copy: expected %d bytes, got %d", length, copied)
	}

	return buf, nil
}

func generateSignature(this js.Value, args []js.Value) interface{} {
	if len(args) != 6 {
		return map[string]interface{}{
			"error": "generateSignature requires exactly 6 argument (data)",
		}
	}

	paramSet := args[0].String()
	sk, _ := getBytesFromWeb(args[1])
	msg, _ := getBytesFromWeb(args[2])
	context, _ := getBytesFromWeb(args[3])
	useAdditionalRandomness, _ := getBoolFromWeb(args[4])
	prehash := args[5].String()

	if len(msg) <= 0 {
		return map[string]interface{}{
			"error": "Message can't be empty.",
		}
	}

	ctx, err := slhdsa.New(paramSet)

	if err != nil {
		return map[string]interface{}{
			"error": err.Error(),
		}
	}

	_sk, err := ctx.GetPrivateKeyFromBytes(sk)

	if err != nil {
		return map[string]interface{}{
			"error": err.Error(),
		}
	}

	sig, err := ctx.GenerateSignature(_sk, msg, context, useAdditionalRandomness, prehash)

	if err != nil {
		return map[string]interface{}{
			"error": err.Error(),
		}
	}

	return map[string]interface{}{
		"signature": base64.StdEncoding.EncodeToString(sig),
		"error":     nil,
	}
}

func verifySignature(this js.Value, args []js.Value) interface{} {
	if len(args) != 6 {
		return map[string]interface{}{
			"error": "verifySignature requires exactly 5 argument (data)",
		}
	}

	paramSet := args[0].String()
	pk, _ := getBytesFromWeb(args[1])
	msg, _ := getBytesFromWeb(args[2])
	sig, _ := getBytesFromWeb(args[3])
	context, _ := getBytesFromWeb(args[4])
	prehash := args[5].String()

	if len(msg) <= 0 {
		return map[string]interface{}{
			"error": "Message can't be empty.",
		}
	}

	if len(sig) <= 0 {
		return map[string]interface{}{
			"error": "Signature can't be empty.",
		}
	}

	ctx, err := slhdsa.New(paramSet)

	if err != nil {
		return map[string]interface{}{
			"error": err.Error(),
		}
	}

	_pk, err := ctx.GetPublicKeyFromBytes(pk)

	if err != nil {
		return map[string]interface{}{
			"error": err.Error(),
		}
	}

	verified, err := ctx.VerifySignature(_pk, msg, sig, context, prehash)

	if err != nil {
		return map[string]interface{}{
			"error": err.Error(),
		}
	}

	return map[string]interface{}{
		"isVerified": verified,
		"error":      nil,
	}
}

// func regularExample() {
// 	sigRegular()
// 	sigContext()
// 	sigRandomness()
// 	sigPrehash()
// }

func wasmExample() {
	js.Global().Set("generateKeyPair", js.FuncOf(generateKeyPair))
	js.Global().Set("generateSignature", js.FuncOf(generateSignature))
	js.Global().Set("verifySignature", js.FuncOf(verifySignature))
}

func main() {
	// regularExample()
	wasmExample()

	select {}
}
