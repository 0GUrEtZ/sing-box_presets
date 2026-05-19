// Package srs implements sing-box binary rule-set (.srs) writer.
// Format reference: https://github.com/SagerNet/sing-box/blob/stable/common/srs/
package srs

import (
	"bufio"
	"compress/zlib"
	"encoding/binary"
	"io"
	"net/netip"
	"os"
	"sort"
)

// Magic bytes and constants from sing-box source.
var magicBytes = [3]byte{0x53, 0x52, 0x53} // "SRS"

const (
	srsVersion      uint8 = 1
	ipSetVersion    uint8 = 1
	ruleTypeDefault uint8 = 0
	ruleItemIPCIDR  uint8 = 6
	ruleItemFinal   uint8 = 0xFF
)

type ipRange struct {
	from [4]byte
	to   [4]byte
}

// WriteCIDRFile записывает список IPv4 CIDR-строк в .srs файл.
func WriteCIDRFile(path string, cidrs []string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return WriteCIDR(f, cidrs)
}

// WriteCIDR записывает список IPv4 CIDR-строк в writer в формате .srs.
func WriteCIDR(w io.Writer, cidrs []string) error {
	ranges, err := cidrsToRanges(cidrs)
	if err != nil {
		return err
	}
	ranges = mergeRanges(ranges)

	// Header: magic + version
	if _, err := w.Write(magicBytes[:]); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, srsVersion); err != nil {
		return err
	}

	// Body: zlib compressed
	zw, err := zlib.NewWriterLevel(w, zlib.BestCompression)
	if err != nil {
		return err
	}
	bw := bufio.NewWriter(zw)

	// 1 rule
	if err := writeUvarint(bw, 1); err != nil {
		return err
	}

	// Rule type: default (0)
	if err := bw.WriteByte(ruleTypeDefault); err != nil {
		return err
	}

	// Item: ruleItemIPCIDR
	if err := bw.WriteByte(ruleItemIPCIDR); err != nil {
		return err
	}

	// IPSet
	if err := writeIPSet(bw, ranges); err != nil {
		return err
	}

	// Final marker
	if err := bw.WriteByte(ruleItemFinal); err != nil {
		return err
	}

	if err := bw.Flush(); err != nil {
		return err
	}
	return zw.Close()
}

func writeIPSet(w *bufio.Writer, ranges []ipRange) error {
	// IPSet version
	if err := w.WriteByte(ipSetVersion); err != nil {
		return err
	}
	// Number of ranges: uint64 big endian
	if err := binary.Write(w, binary.BigEndian, uint64(len(ranges))); err != nil {
		return err
	}
	for _, r := range ranges {
		// from: uvarint(4) + 4 bytes
		if err := writeUvarint(w, 4); err != nil {
			return err
		}
		if _, err := w.Write(r.from[:]); err != nil {
			return err
		}
		// to: uvarint(4) + 4 bytes
		if err := writeUvarint(w, 4); err != nil {
			return err
		}
		if _, err := w.Write(r.to[:]); err != nil {
			return err
		}
	}
	return nil
}

func cidrsToRanges(cidrs []string) ([]ipRange, error) {
	var result []ipRange
	for _, s := range cidrs {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			// bare IP
			a, err2 := netip.ParseAddr(s)
			if err2 != nil {
				continue
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		p = p.Masked()
		if !p.Addr().Is4() {
			continue // skip IPv6
		}
		from := p.Addr().As4()
		// last address = network | ^mask
		bits := p.Bits()
		var to [4]byte
		fromU := binary.BigEndian.Uint32(from[:])
		var maskBits uint32
		if bits == 0 {
			maskBits = 0
		} else {
			maskBits = ^uint32((1 << (32 - bits)) - 1)
		}
		toU := fromU | ^maskBits
		binary.BigEndian.PutUint32(to[:], toU)
		result = append(result, ipRange{from: from, to: to})
	}
	return result, nil
}

func mergeRanges(ranges []ipRange) []ipRange {
	if len(ranges) == 0 {
		return nil
	}
	sort.Slice(ranges, func(i, j int) bool {
		fi := binary.BigEndian.Uint32(ranges[i].from[:])
		fj := binary.BigEndian.Uint32(ranges[j].from[:])
		return fi < fj
	})

	merged := []ipRange{ranges[0]}
	for _, r := range ranges[1:] {
		last := &merged[len(merged)-1]
		lastTo := binary.BigEndian.Uint32(last.to[:])
		curFrom := binary.BigEndian.Uint32(r.from[:])
		curTo := binary.BigEndian.Uint32(r.to[:])

		if curFrom <= lastTo+1 {
			// overlap or adjacent — extend
			if curTo > lastTo {
				binary.BigEndian.PutUint32(last.to[:], curTo)
			}
		} else {
			merged = append(merged, r)
		}
	}
	return merged
}

func writeUvarint(w *bufio.Writer, v uint64) error {
	var buf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(buf[:], v)
	_, err := w.Write(buf[:n])
	return err
}
