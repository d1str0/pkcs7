package pkcs7

import (
	"bytes"
	"strings"
	"testing"
)

type testVector struct {
	blockSize   int
	input       []byte
	output      []byte
	errorString string
}

var padTests = []testVector{
	// Pads buffers.
	{
		16,
		[]byte{
			0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
			0xDE, 0xAD, 0xBE, 0xEF,
		},
		[]byte{
			0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
			0xDE, 0xAD, 0xBE, 0xEF, 0x04, 0x04, 0x04, 0x04,
		},
		"",
	},

	// Pads empty buffers.
	{
		16,
		[]byte{},
		[]byte{
			0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
			0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
		},
		"",
	},

	// Pads buffers larger than the block size.
	{
		16,
		[]byte{
			0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
			0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
			0xDE, 0xAD, 0xBE, 0xEF,
		},
		[]byte{
			0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
			0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
			0xDE, 0xAD, 0xBE, 0xEF, 0x0C, 0x0C, 0x0C, 0x0C,
			0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C,
		},
		"",
	},
	// Error when block size is more than 255
	{
		256,
		[]byte{0x01, 0x02, 0x03, 0x04},
		nil,
		"pkcs7: block size must be between 1 and 255 inclusive",
	},
	// (Pad only) Error when block size is zero
	{
		0,
		[]byte{0x01, 0x02, 0x03, 0x04},
		nil,
		"pkcs7: block size must be between 1 and 255 inclusive",
	},
	// (Unpad only) Error when padded block  has a final zero bit
	{
		4,
		nil,
		[]byte{0x01, 0x02, 0x03, 0x00},
		"pkcs7: invalid padding",
	},
}

func TestPad(t *testing.T) {
	for i, v := range padTests {
		if v.input != nil {
			o, err := Pad(v.input, v.blockSize)
			if err != nil {
				if v.errorString == "" {
					t.Errorf("Padding caused error: %v", err)
				} else if !strings.Contains(err.Error(), v.errorString) {
					t.Errorf("Unexpected error: we expected %s but we received %v", v.errorString, err)
					return
				}
			}
			if v.output != nil {
				if !bytes.Equal(o, v.output) {
					t.Errorf("Pad %d: expected %x, got %x", i, v.output, o)
				}
			}
		}
	}
}

func TestUnpad(t *testing.T) {
	for i, v := range padTests {
		if v.output != nil {
			o, err := Unpad(v.output)
			if err != nil {
				if v.errorString == "" {
					t.Errorf("Padding caused error: %v", err)
				} else if !strings.Contains(err.Error(), v.errorString) {
					t.Errorf("Unexpected error: we expected %s but we received %v", v.errorString, err)
					return
				}
			}
			if v.input != nil {
				if !bytes.Equal(o, v.input) {
					t.Errorf("Unpad %d: expected %x, got %x", i, v.output, o)
				}
			}
		}
	}
}
