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
	"regexp"
	"strconv"
	"strings"
)

type ruleParser struct {
	packets       uint64
	bytes         uint64
	countersOk    bool
	current       string
	currentValues []string
	chain         string
	flags         []string
}

type ruleChefParser struct {
	current       string
	currentValues []string
	chain         string
	flags         []string
}

var (
	destinationRegexp     = regexp.MustCompile(`^d\s.*`)
	destinationPortRegexp = regexp.MustCompile(`^dports\s.*`)  //DestinationPort
	commentRegexp         = regexp.MustCompile(`^comment\s.*`) // Match
	protocolRegexp        = regexp.MustCompile(`^p\s.*`)       //Protocol
	sourceRegexp          = regexp.MustCompile(`^s\s.*`)
	sourcePortRegexp      = regexp.MustCompile(`^sport\s.*`) //SourcePort
	targetRegexp          = regexp.MustCompile(`^j\s.*`)     //Target
)

func (p *ruleParser) flush() {
	switch p.current {
	case "":
		// Ignore
	case "-A", "--append":
		if len(p.currentValues) > 0 {
			p.chain = p.currentValues[0]
		}
	default:
		p.flags = append(p.flags, p.current)
		p.flags = append(p.flags, p.currentValues...)
	}
	p.current = ""
	p.currentValues = nil
}

func (p *ruleChefParser) flush() {
	switch p.current {
	case "":
		// Ignore
	case "-A", "--append":
		if len(p.currentValues) > 0 {
			p.chain = p.currentValues[0]
		}
	default:
		p.flags = append(p.flags, p.current)
		p.flags = append(p.flags, p.currentValues...)
	}
	p.current = ""
	p.currentValues = nil
}

func (p *ruleChefParser) handleToken(token string) {
	if strings.HasPrefix(token, "-") {
		p.flush()
		p.current = token
		return
	}
	p.currentValues = append(p.currentValues, token)
}

func (p *ruleParser) handleToken(token string) {
	if strings.HasPrefix(token, "[") {
		p.packets, p.bytes, p.countersOk = parseCounters(token)
		return
	}
	if strings.HasPrefix(token, "-") {
		p.flush()
		p.current = token
		return
	}
	p.currentValues = append(p.currentValues, token)
}

func (r *Rule) populateFlags(flags []string) {
	parsedFlags := strings.Split(strings.Join(flags, " "), "-")
	for i := range parsedFlags {
		switch {
		case destinationRegexp.MatchString(parsedFlags[i]):
			r.Destination = strings.Split(parsedFlags[i], " ")[1]
		case destinationPortRegexp.MatchString(parsedFlags[i]):
			r.DestinationPort, _ = strconv.Atoi(strings.Split(parsedFlags[i], " ")[1])
		case commentRegexp.MatchString(parsedFlags[i]):
			r.Match = strings.Split(parsedFlags[i], " ")[1]
		case protocolRegexp.MatchString(parsedFlags[i]):
			r.Protocol = strings.Split(parsedFlags[i], " ")[1]
		case sourceRegexp.MatchString(parsedFlags[i]):
			r.Source = strings.Split(parsedFlags[i], " ")[1]
		case sourcePortRegexp.MatchString(parsedFlags[i]):
			r.SourcePort, _ = strconv.Atoi(strings.Split(parsedFlags[i], " ")[1])
		case targetRegexp.MatchString(parsedFlags[i]):
			r.Target = strings.Split(parsedFlags[i], " ")[1]
		case targetRegexp.MatchString(parsedFlags[i]):
			r.ChefSync = strings.Split(parsedFlags[i], " ")[1]
		}
	}

	if r.Destination == "" {
		r.Destination = "0.0.0.0/32"
	}
	if r.Source == "" {
		r.Source = "0.0.0.0/32"
	}
}
