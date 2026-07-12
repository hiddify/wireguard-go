package hiddify

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

type NoiseOptions struct {
	FakePacket FakePacketOptions `json:"fake_packet"`
}

type FakePacketOptions struct {
	Enabled  bool   `json:"enabled,omitempty"`
	Count    Range  `json:"count,omitempty"`
	Size     Range  `json:"size,omitempty"`
	Delay    Range  `json:"delay,omitempty"`
	Mode     string `json:"mode,omitempty"`
	Header   []byte `json:"header,omitempty"`
	NoModify bool   `json:"no_modify,omitempty"`
}

type Range struct {
	From int32 `json:"from"`
	To   int32 `json:"to"`
}

func (c *Range) Build() *Range {
	return (*Range)(c)
}

func (c *Range) MarshalJSON() ([]byte, error) {
	if c.From == 0 && c.To == 0 {
		return json.Marshal("")
	}
	return json.Marshal(fmt.Sprintf("%d-%d", c.From, c.To))
}

func (c *Range) UnmarshalJSON(content []byte) error {
	var rangeValue struct {
		From int32 `json:"from"`
		To   int32 `json:"to"`
	}
	var stringValue string

	if err := json.Unmarshal(content, &stringValue); err == nil {
		if stringValue == "" {
			rangeValue.From, rangeValue.To = 0, 0
		} else {
			parts := strings.Split(stringValue, "-")
			if len(parts) != 2 {
				from, err := strconv.ParseInt(parts[0], 10, 32)
				if err != nil {
					return err
				}
				rangeValue.From, rangeValue.To = int32(from), int32(from)
			} else {
				from, err := strconv.ParseInt(parts[0], 10, 32)
				if err != nil {
					return err
				}
				to, err := strconv.ParseInt(parts[1], 10, 32)
				if err != nil {
					return err
				}
				rangeValue.From, rangeValue.To = int32(from), int32(to)
			}
		}
	} else {
		var intValue int
		if err := json.Unmarshal(content, &intValue); err == nil {
			rangeValue.From, rangeValue.To = int32(intValue), int32(intValue)
		} else if err := json.Unmarshal(content, &rangeValue); err != nil {
			return err
		}

	}
	if rangeValue.From > rangeValue.To {
		return fmt.Errorf("invalid range")
	}
	*c = Range{rangeValue.From, rangeValue.To}
	return nil
}
func (c Range) Rand() int {
	return int(RandBetween(int64(c.From), int64(c.To)))
}

func RandBetween(from int64, to int64) int64 {
	if from == to {
		return from
	}
	if from > to {
		from, to = to, from
	}
	bigInt, _ := rand.Int(rand.Reader, big.NewInt(to-from))
	return from + bigInt.Int64()
}
