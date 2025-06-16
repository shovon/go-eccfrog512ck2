package eccfrog512ck2

import (
	"fmt"
	"math/big"
)

var (
	p  *big.Int = &big.Int{}
	n  *big.Int = &big.Int{}
	gX *big.Int = &big.Int{}
	gY *big.Int = &big.Int{}
	a  *big.Int = &big.Int{}
	b  *big.Int = &big.Int{}
)

func init() {
	p, _ = p.SetString("9149012705592502490164965176888130701548053918699793689672344807772801105830681498780746622530729418858477103073591918058480028776841126664954537807339721", 10)
	n, _ = n.SetString("9149012705592502490164965176888130701548053918699793689672344807772801105830557269123255850915745063541133157503707284048429261692283957712127567713136519", 10)
	gX, _ = gX.SetString("8426241697659200371183582771153260966569955699615044232640972423431947060129573736112298744977332416175021337082775856058058394786264506901662703740544432", 10)
	gY, _ = gY.SetString("4970129934163735248083452609809843496231929620419038489506391366136186485994288320758668172790060801809810688192082146431970683113557239433570011112556001", 10)
	a = a.Set(p).Sub(a, big.NewInt(7))
	b, _ = b.SetString("95864189850957917703933006131793785649240252916618759767550461391845895018181", 10)
}

type coordinate[T any] [2]T

type maybe[T comparable] struct {
	has   bool
	value T
}

func something[T comparable](value T) maybe[T] {
	return maybe[T]{has: true, value: value}
}

func nothing[T comparable]() maybe[T] {
	return maybe[T]{}
}

func (m maybe[T]) Extract() (T, bool) {
	return m.value, m.has
}

// CurvePoint represents a point on the EccFrog512CK2 elliptic curve.
// It can either be a finite point with x,y coordinates or the point at
// infinity.
type CurvePoint maybe[coordinate[*big.Int]]

// PointAtInfinity gets the point at infinity for the EccFrog512Ck2 elliptic
// curve.
func PointAtInfinity() CurvePoint {
	return CurvePoint(nothing[coordinate[*big.Int]]())
}

// CoordinateIfNotInfinity returns the x and y coordinates of the curve point if
// it is not the point at infinity. If the point is at infinity, it returns nil,
// nil, false. Otherwise it returns copies of the x and y coordinates along with
// true.
//
// The returned coordinates are copies of the internal values to prevent
// mutation.
func (c CurvePoint) CoordinateIfNotInfinity() (*big.Int, *big.Int, bool) {
	if c == PointAtInfinity() {
		return nil, nil, false
	}

	x := new(big.Int).Set(c.value[0])
	y := new(big.Int).Set(c.value[1])
	return x, y, true
}

func (c CurvePoint) add(b CurvePoint) CurvePoint {
	p1, ok1 := maybe[coordinate[*big.Int]](c).Extract()
	p2, ok2 := maybe[coordinate[*big.Int]](b).Extract()

	if !ok1 {
		return b
	}

	if !ok2 {
		return c
	}

	m := &big.Int{}
	x := &big.Int{}
	y := &big.Int{}

	if c.equal(b) {
		// Calculate the slope (m) of the tangent line
		numerator := new(big.Int).Mul(big.NewInt(3), new(big.Int).Mul(p1[0], p1[0]))
		numerator.Add(numerator, a)
		// TODO: unit test to find a point such that `p1[1] == 0`.
		denominator := new(big.Int).Mul(big.NewInt(2), p1[1])
		if denominator.Cmp(big.NewInt(0)) == 0 {
			return PointAtInfinity()
		}
		m.Mul(numerator, (&big.Int{}).ModInverse(denominator, p))
		m.Mod(m, p)
	} else {
		// fmt.Printf("Not equal! %v %v\n", c, i)
		// Calculate the slope (m) of the secant line
		numerator := new(big.Int).Sub(p2[1], p1[1])
		denominator := new(big.Int).Sub(p2[0], p1[0])
		if denominator.Cmp(big.NewInt(0)) == 0 {
			return PointAtInfinity()
		}
		m.Mul(numerator, (&big.Int{}).ModInverse(denominator, p))
		m.Mod(m, p)
	}

	// Calculate x3 = m^2 - x2 - x1 (mod p)
	x.Mul(m, m)
	x.Sub(x, p1[0])
	x.Sub(x, p2[0])
	x.Mod(x, p)

	// Calculate y3 = m(x1 - x3) - y1 (mod p)
	y.Sub(p1[0], x)
	y.Mul(y, m)
	y.Sub(y, p1[1])
	y.Mod(y, p)

	return CurvePoint(something(coordinate[*big.Int]{x, y}))
}

// Add adds two points on the curve and returns their sum. The method ensures that
// both points are valid curve points and returns a new point that is also on the
// curve. This is the public interface for point addition - it performs validation
// whereas the internal add() method does not.
func (c CurvePoint) Add(b CurvePoint) CurvePoint {
	sum := c.add(b)
	assertInCurve(sum)
	return sum
}

// Multiply performs scalar multiplication of a curve point with a big integer n,
// returning the resulting curve point. It uses the double-and-add algorithm to
// efficiently compute n*P where P is the input curve point. The method ensures
// the result is a valid curve point.
//
// The algorithm works by scanning the bits of n from least to most significant.
// For each bit that is 1, the current point is added to the result, and for
// each bit (0 or 1) the current point is doubled.
func (c CurvePoint) Multiply(n *big.Int) CurvePoint {
	result := PointAtInfinity()
	temp := c
	for i := 0; i < n.BitLen(); i++ {
		if n.Bit(i) == 1 {
			result = result.Add(temp)
		}
		temp = temp.Add(temp)
	}
	assertInCurve(result)
	return result
}

func (c CurvePoint) equal(b CurvePoint) bool {
	p1, ok1 := maybe[coordinate[*big.Int]](c).Extract()
	p2, ok2 := maybe[coordinate[*big.Int]](b).Extract()

	if !ok1 && !ok2 {
		return true
	}

	if ok1 != ok2 {
		return false
	}

	return p1[0].Cmp(p2[0]) == 0 && p1[1].Cmp(p2[1]) == 0
}

// Equal returns true if the curve point b equals to the receiver curve point c.
func (c CurvePoint) Equal(b CurvePoint) bool {
	assertInCurve(c)
	assertInCurve(b)

	return c.equal(b)
}

// GeneratorOrder represents the total number of unique points (including the
// point at infinity) of the generator of the EccFrog512Ck2 curve, and is
// represented by the number:
//
// 9149012705592502490164965176888130701548053918699793689672344807772801105830557269123255850915745063541133157503707284048429261692283957712127567713136519
func GeneratorOrder() *big.Int {
	return (&big.Int{}).Set(n)
}

// Generator gets the generator of the EccFrog512Ck2 curve.
func Generator() CurvePoint {
	return CurvePoint(something(coordinate[*big.Int]{gX, gY}))
}

func IsCoordinateInCurve(point coordinate[*big.Int]) bool {
	// Compute left-hand side of curve equation: y^2
	lhs := (&big.Int{}).Mul(point[1], point[1])
	lhs.Mod(lhs, p)

	// Compute right-hand side of curve equation: x^3 + ax + b
	rhs := (&big.Int{}).Mul(point[0], point[0])
	rhs.Mul(rhs, point[0])
	rhs.Mod(rhs, p)

	ax := (&big.Int{}).Mul(a, point[0])
	ax.Mod(ax, p)

	rhs.Add(rhs, ax)
	rhs.Add(rhs, b)
	rhs.Mod(rhs, p)

	cmp := lhs.Cmp(rhs) == 0

	return cmp
}

func assertInCurve(c CurvePoint) {
	point, ok := maybe[coordinate[*big.Int]](c).Extract()
	if !ok {
		return
	}

	if !IsCoordinateInCurve(point) {
		panic("The point is not in the curve")
	}
}

// A returns the curve parameter a in the equation y^2 = x^3 + ax + b.
func A() *big.Int {
	return (&big.Int{}).Set(a)
}

// B returns the curve parameter b in the equation y^2 = x^3 + ax + b.
func B() *big.Int {
	return (&big.Int{}).Set(b)
}

// P returns the prime field characteristic p of the curve.
func P() *big.Int {
	return (&big.Int{}).Set(p)
}

var _ fmt.Stringer = CurvePoint{}
var _ fmt.GoStringer = CurvePoint{}
var _ fmt.Formatter = CurvePoint{}

// String returns a string representation of the CurvePoint.
// Returns "O" for the point at infinity, otherwise returns "(x, y)".
func (c CurvePoint) String() string {
	coord, ok := maybe[coordinate[*big.Int]](c).Extract()
	if !ok {
		return "(point at infinity)"
	}
	return fmt.Sprintf("(%s, %s)", coord[0].String(), coord[1].String())
}

// GoString returns a Go-syntax representation of the CurvePoint.
func (c CurvePoint) GoString() string {
	coord, ok := maybe[coordinate[*big.Int]](c).Extract()
	if !ok {
		return "PointAtInfinity()"
	}
	return fmt.Sprintf("CurvePoint{X: %#v, Y: %#v}", coord[0], coord[1])
}

// Format implements fmt.Formatter for custom formatting.
func (c CurvePoint) Format(f fmt.State, verb rune) {
	switch verb {
	case 'v':
		if f.Flag('#') {
			fmt.Fprint(f, c.GoString())
		} else {
			fmt.Fprint(f, c.String())
		}
	case 's':
		fmt.Fprint(f, c.String())
	default:
		fmt.Fprintf(f, "%%!%c(CurvePoint=%s)", verb, c.String())
	}
}

// NewCurvePoint creates a new curve point from raw x and y coordinates.
// Returns an error if the point is not on the curve.
func NewCurvePoint(x, y *big.Int) (CurvePoint, error) {
	point := coordinate[*big.Int]{x, y}
	if !IsCoordinateInCurve(point) {
		return CurvePoint{}, fmt.Errorf("point (%v, %v) is not on the curve", x, y)
	}
	return CurvePoint(something(point)), nil
}

// MarshalSEC1 serializes the curve point in SEC1 format.
// The output can be either:
// - Uncompressed: 0x04 || x || y (129 bytes)
// - Compressed: 0x02 || x or 0x03 || x (65 bytes)
// where x and y are the coordinates in big-endian format.
//
// If the point is at infinity, returns nil.
// If compressed is true, uses compressed format (0x02 or 0x03 prefix based on y coordinate).
// If compressed is false, uses uncompressed format (0x04 prefix).
func (c CurvePoint) MarshalSEC1(compressed bool) []byte {
	coord, ok := maybe[coordinate[*big.Int]](c).Extract()
	if !ok {
		return nil
	}

	x := coord[0].Bytes()
	y := coord[1].Bytes()

	// Pad x and y to 64 bytes if needed
	if len(x) < 64 {
		x = append(make([]byte, 64-len(x)), x...)
	}
	if len(y) < 64 {
		y = append(make([]byte, 64-len(y)), y...)
	}

	if !compressed {
		// Uncompressed format: 0x04 || x || y
		return append([]byte{0x04}, append(x, y...)...)
	}

	// Compressed format: 0x02 || x or 0x03 || x
	// Use 0x02 if y is even, 0x03 if y is odd
	prefix := byte(0x02)
	if y[len(y)-1]&1 == 1 {
		prefix = 0x03
	}
	return append([]byte{prefix}, x...)
}
