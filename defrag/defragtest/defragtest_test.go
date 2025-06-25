package defragtest_test

import (
	"fmt"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/gopacket/defrag/defragtest"
)

func TestFragmentingBytes(t *testing.T) {
	var tests = []struct {
		message []byte
		chunks  int
		want    [][]byte
	}{
		{
			message: []byte("123456789ABCDEF"),
			chunks:  1,
			want: [][]byte{
				[]byte("123456789ABCDEF"),
			},
		},
		{
			message: []byte("123456789ABCDEF"),
			chunks:  2,
			want: [][]byte{
				[]byte("12345678"),
				[]byte("9ABCDEF"),
			},
		},
		{
			message: []byte("123456789ABCDEF"),
			chunks:  3,
			want: [][]byte{
				[]byte("12345"),
				[]byte("6789A"),
				[]byte("BCDEF"),
			},
		},
	}

	for _, tt := range tests {
		t.Logf("Splitting %d bytes into %d chunks", len(tt.message), tt.chunks)
		if len(tt.want) != tt.chunks {
			// This panic is here to protect against unintentional modifications that void
			// the test cases.
			panic(fmt.Sprintf("Invalid test-case splits into wrong number of chunks: chunks=%d, len(want)=%d", tt.chunks, len(tt.want)))
		}
		parts := slices.Collect(defragtest.FragmentBytes(tt.message, tt.chunks))
		if diff := cmp.Diff(parts, tt.want); diff != "" {
			t.Errorf("FragmentUserData() mismatch (-want +got):\n%s", diff)
		}
	}
}
