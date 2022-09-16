// Copyright 2018 RetailNext, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package iptables

import (
	"os"
	"testing"

	"github.com/go-test/deep"
)

type parserTestCase struct {
	name     string
	expected Tables
}

func (c parserTestCase) run() ([]string, error) {
	f, err := os.Open(c.name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	result, err := ParseIptablesSave(f)
	if err != nil {
		return nil, err
	}
	return deep.Equal(c.expected, result), nil
}

var parserTestCases = []parserTestCase{
	{
		name: "server.iptables-save",
		expected: Tables{
			"filter": {
				"INPUT": {
					Policy:  "ACCEPT",
					Packets: 8202915326,
					Bytes:   443356185985,
					Rules: []Rule{
						{
							Packets:         7981319024,
							Bytes:           1536987862973,
							Protocol:        "tcp",
							Match:           "tcp",
							DestinationPort: 7000,
							Target:          "ACCEPT",
						},
						{
							Packets:         1335166082,
							Bytes:           279365222746,
							Protocol:        "tcp",
							Match:           "tcp",
							DestinationPort: 9160,
							Target:          "ACCEPT",
						},
						{
							Packets:         27438740,
							Bytes:           6089401408,
							Protocol:        "tcp",
							Match:           "tcp",
							DestinationPort: 7199,
							Target:          "ACCEPT",
						},
						{
							Packets:         1285509559,
							Bytes:           346897300390,
							Protocol:        "tcp",
							Match:           "tcp",
							DestinationPort: 9042,
							Target:          "ACCEPT",
						},
					},
				},
				"FORWARD": {
					Policy: "ACCEPT",
				},
				"OUTPUT": {
					Policy:  "ACCEPT",
					Packets: 8189941891,
					Bytes:   1885661899958,
					Rules: []Rule{
						{
							Packets:    7903596488,
							Bytes:      341918393697,
							Protocol:   "tcp",
							Match:      "tcp",
							SourcePort: 7000,
							Target:     "ACCEPT",
						},
						{
							Packets:    973128122,
							Bytes:      70345269557,
							Protocol:   "tcp",
							Match:      "tcp",
							SourcePort: 9160,
							Target:     "ACCEPT",
						},
						{
							Packets:    26463368,
							Bytes:      3097440049,
							Protocol:   "tcp",
							Match:      "tcp",
							SourcePort: 7199,
							Target:     "ACCEPT",
						},
						{
							Packets:    813815825,
							Bytes:      429136005552,
							Protocol:   "tcp",
							Match:      "tcp",
							SourcePort: 9042,
							Target:     "ACCEPT",
						},
					},
				},
			},
			"mangle": {
				"PREROUTING": {
					Policy:  "ACCEPT",
					Packets: 18832348733,
					Bytes:   2612695974158,
				},
				"INPUT": {
					Policy:  "ACCEPT",
					Packets: 18832348731,
					Bytes:   2612695973502,
				},
				"FORWARD": {
					Policy: "ACCEPT",
				},
				"OUTPUT": {
					Policy:  "ACCEPT",
					Packets: 17906945694,
					Bytes:   2730159008813,
				},
				"POSTROUTING": {
					Policy:  "ACCEPT",
					Packets: 17906945694,
					Bytes:   2730159008813,
				},
			},
		},
	},
}

func TestParseIptablesSave(t *testing.T) {
	for _, tc := range parserTestCases {
		mismatch, err := tc.run()
		if err != nil {
			t.Fatalf("%s: %+v", tc.name, err)
		}
		if mismatch != nil {
			t.Fatalf("%s: %+v", tc.name, mismatch)
		}
	}
}
