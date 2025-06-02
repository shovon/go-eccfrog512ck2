package eccfrog512ck2_test

import (
	"math/big"
	"testing"

	"github.com/shovon/go-eccfrog512ck2"
)

func TestCoordinateIfNotInfinity(t *testing.T) {
	t.Run("point at infinity", func(t *testing.T) {
		if _, _, ok := eccfrog512ck2.PointAtInfinity().CoordinateIfNotInfinity(); ok {
			t.Fail()
		}
	})
}

func TestAdd(t *testing.T) {
	t.Run("rhs is point at infinity", func(t *testing.T) {
		a := eccfrog512ck2.Generator()
		b := eccfrog512ck2.PointAtInfinity()

		if !a.Add(b).Equal(a) {
			t.Fail()
		}
	})
}

func TestOrderOfCurve(t *testing.T) {
	if !eccfrog512ck2.Generator().Multiply(eccfrog512ck2.GeneratorOrder()).Equal(eccfrog512ck2.PointAtInfinity()) {
		t.Fail()
	}
}

func TestEqual(t *testing.T) {
	t.Run("rhs is pointa t infinity", func(t *testing.T) {
		a := eccfrog512ck2.Generator()
		b := eccfrog512ck2.PointAtInfinity()

		if a.Equal(b) {
			t.Fail()
		}
	})
}

func TestZeroValue(t *testing.T) {
	if (eccfrog512ck2.CurvePoint{}) != eccfrog512ck2.PointAtInfinity() {
		t.Fail()
	}
}

func TestPointInInfinityIsInCurve(t *testing.T) {
	eccfrog512ck2.PointAtInfinity().Add(eccfrog512ck2.PointAtInfinity())
}

func TestIsGeneratorInCurve(t *testing.T) {
	_, _, ok := eccfrog512ck2.Generator().CoordinateIfNotInfinity()

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
