// Command genicon renders the Fluxify icon (three uplinks converging into one
// bonded stream) and writes multi-resolution .ico files used for the Windows
// executable resource and the system-tray icon.
//
// Usage: go run ./scripts/genicon
package main

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"log"
	"os"
	"path/filepath"
)

var (
	bgColor     = color.NRGBA{R: 0x11, G: 0x18, B: 0x27, A: 0xFF} // dark slate
	streamColor = color.NRGBA{R: 0xF8, G: 0xFA, B: 0xFC, A: 0xFF} // near white
	linkColors  = []color.NRGBA{
		{R: 0x22, G: 0xD3, B: 0xEE, A: 0xFF}, // cyan
		{R: 0x81, G: 0x8C, B: 0xF8, A: 0xFF}, // violet
		{R: 0xFB, G: 0xBF, B: 0x24, A: 0xFF}, // amber
	}
	grayLink = color.NRGBA{R: 0x6B, G: 0x72, B: 0x80, A: 0xFF}
	grayBg   = color.NRGBA{R: 0x1F, G: 0x29, B: 0x37, A: 0xFF}
)

func main() {
	outDir := filepath.Join("client", "assets")
	if err := os.MkdirAll(outDir, 0755); err != nil {
		log.Fatalf("mkdir %s: %v", outDir, err)
	}
	sizes := []int{16, 24, 32, 48, 64, 128, 256}

	write := func(name string, gray bool) {
		var frames [][]byte
		for _, s := range sizes {
			frames = append(frames, encodePNG(render(s, gray)))
		}
		path := filepath.Join(outDir, name)
		if err := os.WriteFile(path, buildICO(sizes, frames), 0644); err != nil {
			log.Fatalf("write %s: %v", path, err)
		}
		log.Printf("wrote %s (%d sizes)", path, len(sizes))
	}
	write("fluxify.ico", false)
	write("fluxify-off.ico", true)
}

// render draws the icon at the given size: a dark round badge with three
// colored links on the left merging into a single thick stream on the right.
func render(size int, gray bool) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	s := float64(size)
	cx, cy, r := s/2, s/2, s/2

	bg := bgColor
	if gray {
		bg = grayBg
	}

	// Geometry in unit coordinates (0..1), scaled per pixel.
	linkYs := []float64{0.34, 0.50, 0.66} // left band centers
	linkX0, linkX1 := 0.14, 0.52          // converging zone
	streamX1 := 0.88                      // bonded stream end
	linkT := 0.055 * s                    // link half-thickness
	streamT := 0.10 * s                   // stream half-thickness

	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			fx, fy := float64(x)+0.5, float64(y)+0.5

			// Round badge with anti-aliased edge.
			dx, dy := fx-cx, fy-cy
			dist := dx*dx + dy*dy
			edge := r - 0.6
			if dist > r*r {
				continue
			}
			a := 1.0
			if dist > edge*edge {
				a = (r - sqrt(dist)) / (r - edge)
				if a < 0 {
					a = 0
				}
			}

			c := bg
			ux := fx / s
			switch {
			case ux >= linkX0 && ux < linkX1:
				// Three links converging toward the center line.
				t := (ux - linkX0) / (linkX1 - linkX0)
				for i, ly := range linkYs {
					centerY := (ly + (0.5-ly)*t) * s
					if abs(fy-centerY) <= linkT {
						if gray {
							c = grayLink
						} else {
							c = linkColors[i]
						}
					}
				}
			case ux >= linkX1 && ux <= streamX1:
				// Single bonded stream.
				if abs(fy-cy) <= streamT {
					if gray {
						c = grayLink
					} else {
						c = streamColor
					}
				}
			}

			c.A = uint8(a * 255)
			img.SetNRGBA(x, y, c)
		}
	}
	return img
}

func abs(v float64) float64 {
	if v < 0 {
		return -v
	}
	return v
}

func sqrt(v float64) float64 {
	// Newton iterations are plenty for pixel-level precision.
	if v <= 0 {
		return 0
	}
	g := v / 2
	for i := 0; i < 12; i++ {
		g = (g + v/g) / 2
	}
	return g
}

func encodePNG(img image.Image) []byte {
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		log.Fatalf("png encode: %v", err)
	}
	return buf.Bytes()
}

// buildICO wraps PNG frames into a .ico container (PNG entries are supported
// since Windows Vista).
func buildICO(sizes []int, frames [][]byte) []byte {
	var buf bytes.Buffer
	// ICONDIR
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0)) // reserved
	_ = binary.Write(&buf, binary.LittleEndian, uint16(1)) // type: icon
	_ = binary.Write(&buf, binary.LittleEndian, uint16(len(frames)))

	offset := 6 + 16*len(frames)
	for i, data := range frames {
		dim := byte(sizes[i])
		if sizes[i] >= 256 {
			dim = 0
		}
		buf.WriteByte(dim)                                      // width
		buf.WriteByte(dim)                                      // height
		buf.WriteByte(0)                                        // palette
		buf.WriteByte(0)                                        // reserved
		_ = binary.Write(&buf, binary.LittleEndian, uint16(1))  // planes
		_ = binary.Write(&buf, binary.LittleEndian, uint16(32)) // bpp
		_ = binary.Write(&buf, binary.LittleEndian, uint32(len(data)))
		_ = binary.Write(&buf, binary.LittleEndian, uint32(offset))
		offset += len(data)
	}
	for _, data := range frames {
		buf.Write(data)
	}
	return buf.Bytes()
}
