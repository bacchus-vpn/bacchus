//go:build windows

// Grape logo, drawn in code and encoded as a Windows .ico (PNG-in-ICO).
package main

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
)

func grapeIcon() []byte {
	const S = 64
	img := image.NewRGBA(image.Rect(0, 0, S, S))

	grape := color.RGBA{0x7b, 0x2c, 0xbf, 0xff} // purple
	hi := color.RGBA{0xb1, 0x7c, 0xe8, 0xff}    // highlight
	stem := color.RGBA{0x6b, 0x46, 0x21, 0xff}  // brown
	leaf := color.RGBA{0x3a, 0xa0, 0x3a, 0xff}  // green

	// stem
	for y := 7; y < 22; y++ {
		for x := 31; x <= 33; x++ {
			img.Set(x, y, stem)
		}
	}
	// leaf
	fillCircle(img, 44, 13, 7, leaf)

	// bunch: wide at top, narrowing to a point
	centers := [][2]int{
		{14, 33}, {50, 33},
		{20, 28}, {32, 28}, {44, 28},
		{26, 38}, {38, 38},
		{32, 48},
	}
	for _, c := range centers {
		fillCircle(img, c[0], c[1], 7, grape)
		fillCircle(img, c[0]-2, c[1]-3, 2, hi) // little shine
	}

	var pngBuf bytes.Buffer
	_ = png.Encode(&pngBuf, img)
	return wrapICO(pngBuf.Bytes(), S, S)
}

func fillCircle(img *image.RGBA, cx, cy, r int, col color.Color) {
	for y := cy - r; y <= cy+r; y++ {
		for x := cx - r; x <= cx+r; x++ {
			dx, dy := x-cx, y-cy
			if dx*dx+dy*dy <= r*r {
				img.Set(x, y, col)
			}
		}
	}
}

// wrapICO packs PNG bytes into a single-image .ico container.
func wrapICO(pngData []byte, w, h int) []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, uint16(0))            // reserved
	binary.Write(&buf, binary.LittleEndian, uint16(1))            // type: icon
	binary.Write(&buf, binary.LittleEndian, uint16(1))            // image count
	buf.WriteByte(byte(w % 256))                                  // width (0 => 256)
	buf.WriteByte(byte(h % 256))                                  // height
	buf.WriteByte(0)                                              // palette
	buf.WriteByte(0)                                              // reserved
	binary.Write(&buf, binary.LittleEndian, uint16(1))            // planes
	binary.Write(&buf, binary.LittleEndian, uint16(32))           // bpp
	binary.Write(&buf, binary.LittleEndian, uint32(len(pngData))) // size
	binary.Write(&buf, binary.LittleEndian, uint32(22))           // offset (6+16)
	buf.Write(pngData)
	return buf.Bytes()
}
