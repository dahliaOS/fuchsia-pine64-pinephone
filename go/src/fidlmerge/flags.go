// Copyright 2018 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package main

import (
	"encoding/json"
	"fidl/compiler/backend/types"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
)

type Options map[string]string

func (o *Options) String() string {
	return fmt.Sprintf("%v", *o)
}

func (o *Options) Set(args string) error {
	for _, option := range strings.Split(args, ",") {
		nameValue := strings.Split(option, "=")
		(*o)[nameValue[0]] = nameValue[1]
	}
	return nil
}

type Flags struct {
	jsonPath     *string
	templatePath *string
	outputBase   *string
}

// GetFlags returns the set of flags.
func GetFlags() Flags {
	return Flags{
		flag.String("json", "",
			"relative path to the FIDL intermediate representation."),
		flag.String("template", "",
			"relative path to the template."),
		flag.String("output-base", "",
			"the base file name for files generated by this generator."),
	}
}

// Valid returns true if the parsed flags are valid.
func (f Flags) Valid() bool {
	return *f.jsonPath != "" && *f.templatePath != "" && *f.outputBase != ""
}

// FidlTypes returns the root FIDL type information from the JSON file specified as an argument.
func (f Flags) FidlTypes() types.Root {
	bytes, err := ioutil.ReadFile(*f.jsonPath)
	if err != nil {
		log.Fatalf("Error reading from %s: %v", *f.jsonPath, err)
	}

	var fidl types.Root
	err = json.Unmarshal(bytes, &fidl)
	if err != nil {
		log.Fatalf("Error parsing JSON as FIDL data: %v", err)
	}

	for _, l := range fidl.Libraries {
		for k, v := range l.Decls {
			fidl.Decls[types.EnsureLibrary(l.Name, k)] = v
		}
	}

	return fidl
}
