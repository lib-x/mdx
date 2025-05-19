//
// Copyright (C) 2023 Quan Chen <chenquan_act@163.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package mdx

import (
	"testing"
)

func TestMdict_Lookup(t *testing.T) {
	mdict, err := New("testdata/现代汉语八百词.mdx")
	if err != nil {
		t.Fatal(err)
	}
	err = mdict.BuildIndex()
	if err != nil {
		t.Fatal(err)
	}
	lookup, err := mdict.Lookup("一律")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(lookup))
}
