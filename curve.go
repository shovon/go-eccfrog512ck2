package eccfrog512ck2

import (
	"crypto/rand"
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

// coordinate represents a generic coordinate.
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

type CurvePoint maybe[coordinate[*big.Int]]

func PointAtInfinity() CurvePoint {
	return CurvePoint(nothing[coordinate[*big.Int]]())
}

func (c CurvePoint) IfNotInfinity(cb func([2]*big.Int)) bool {
	if c == PointAtInfinity() {
		return false
	}

	cb(c.value)

	return true
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
		// fmt.Printf("Equal! %v %v\n", c, i)
		if p1[1].Cmp(big.NewInt(0)) == 0 {
			return PointAtInfinity()
		}
		// Calculate the slope (m) of the tangent line
		numerator := new(big.Int).Mul(big.NewInt(3), new(big.Int).Mul(p1[0], p1[0]))
		numerator.Add(numerator, a)
		denominator := new(big.Int).Mul(big.NewInt(2), p1[1])
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

func (c CurvePoint) Add(b CurvePoint) CurvePoint {
	sum := c.add(b)
	assertInCurve(sum)
	return sum
}

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

func Generator() CurvePoint {
	return CurvePoint(something(coordinate[*big.Int]{gX, gY}))
}

// GeneratePrivateKey generates a random private key.
//
// Effectively a shorthand for `rand.Int(rand.Reader, GeneratorOrder())`
func GeneratePrivateKey() (*big.Int, error) {
	return rand.Int(rand.Reader, n)
}

func GetPublicKey(privateKey *big.Int) CurvePoint {
	return Generator().Multiply(privateKey)
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

func init() {
	p.SetString("9149012705592502490164965176888130701548053918699793689672344807772801105830681498780746622530729418858477103073591918058480028776841126664954537807339721", 10)
	n.SetString("9149012705592502490164965176888130701548053918699793689672344807772801105830557269123255850915745063541133157503707284048429261692283957712127567713136519", 10)
	gX.SetString("8426241697659200371183582771153260966569955699615044232640972423431947060129573736112298744977332416175021337082775856058058394786264506901662703740544432", 10)
	gY.SetString("4970129934163735248083452609809843496231929620419038489506391366136186485994288320758668172790060801809810688192082146431970683113557239433570011112556001", 10)
	a.Set(p).Sub(a, big.NewInt(7))
	b.SetString("95864189850957917703933006131793785649240252916618759767550461391845895018181", 10)
}

// Ensure CurvePoint implements fmt.Stringer interface
var _ fmt.Stringer = CurvePoint{}

// Ensure CurvePoint implements fmt.GoStringer interface
var _ fmt.GoStringer = CurvePoint{}

// Ensure CurvePoint implements fmt.Formatter interface
var _ fmt.Formatter = CurvePoint{}

// String returns a string representation of the CurvePoint.
// Returns "O" for the point at infinity, otherwise returns "(x, y)".
func (c CurvePoint) String() string {
	coord, ok := maybe[coordinate[*big.Int]](c).Extract()
	if !ok {
		return "O"
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
