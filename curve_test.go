package eccfrog512ck2_test

import (
	"math/big"
	"testing"

	"github.com/shovon/go-eccfrog512ck2"
)

func TestZeroValue(t *testing.T) {
	if (eccfrog512ck2.CurvePoint{}) != eccfrog512ck2.PointAtInfinity() {
		t.Fail()
	}
}

func TestPointInInfinityIsInCurve(t *testing.T) {
	eccfrog512ck2.PointAtInfinity().Add(eccfrog512ck2.PointAtInfinity())
}

func TestIsGeneratorInCurve(t *testing.T) {
	ok := eccfrog512ck2.Generator().IfNotInfinity(func(p [2]*big.Int) {
		if !eccfrog512ck2.IsCoordinateInCurve(p) {
			t.Error("Coordinate is not in curve")
			t.Fail()
		}
	})

	if !ok {
		t.Error("The generator is supposed to *not* be the point at infinity!")
		t.FailNow()
	}
}

func TestDouble(t *testing.T) {
	doubled := eccfrog512ck2.Generator().Add(eccfrog512ck2.Generator())

	if !doubled.Equal(eccfrog512ck2.Generator().Multiply(big.NewInt(2))) {
		t.Fail()
	}
}

func TestZero(t *testing.T) {
	doubled := eccfrog512ck2.Generator().Multiply(big.NewInt(0))
	if !doubled.Equal(eccfrog512ck2.PointAtInfinity()) {
		t.Fail()
	}
}

func TestTriple(t *testing.T) {
	tripled := eccfrog512ck2.Generator().Multiply(big.NewInt(2)).Add(eccfrog512ck2.Generator())

	if !tripled.Equal(eccfrog512ck2.Generator().Multiply(big.NewInt(3))) {
		t.Fail()
	}
}
