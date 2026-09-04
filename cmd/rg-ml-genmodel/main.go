// SPDX-License-Identifier: 0BSD
package main

import (
	"fmt"
	"os"

	"github.com/Quad4-Software/ravenguard/internal/ml"
)

func main() {
	path := "assets/ml/base.bin"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	m := ml.DefaultModel()
	if err := m.Save(path); err != nil {
		panic(err)
	}
	fmt.Println(m.Hash)
}
