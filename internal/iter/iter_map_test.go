package iter

import (
	"strconv"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestMap(t *testing.T) {
	tests := []struct {
		name     string
		items    []int
		fn       func(int) int
		expected []int
	}{
		{
			name:     "double each element",
			items:    []int{1, 2, 3, 4, 5},
			fn:       func(x int) int { return x * 2 },
			expected: []int{2, 4, 6, 8, 10},
		},
		{
			name:     "add one to each element",
			items:    []int{0, 1, 2, 3},
			fn:       func(x int) int { return x + 1 },
			expected: []int{1, 2, 3, 4},
		},
		{
			name:     "empty slice",
			items:    []int{},
			fn:       func(x int) int { return x * 2 },
			expected: []int{},
		},
		{
			name:     "single element",
			items:    []int{42},
			fn:       func(x int) int { return x * 2 },
			expected: []int{84},
		},
		{
			name:     "negative numbers",
			items:    []int{-1, -2, -3},
			fn:       func(x int) int { return x * -1 },
			expected: []int{1, 2, 3},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Map(tt.items, tt.fn)
			if diff := cmp.Diff(tt.expected, result); diff != "" {
				t.Errorf("Map() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestMapStringToInt(t *testing.T) {
	tests := []struct {
		name     string
		items    []string
		fn       func(string) int
		expected []int
	}{
		{
			name:     "string length",
			items:    []string{"a", "ab", "abc"},
			fn:       func(s string) int { return len(s) },
			expected: []int{1, 2, 3},
		},
		{
			name:     "empty strings",
			items:    []string{"", "", ""},
			fn:       func(s string) int { return len(s) },
			expected: []int{0, 0, 0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Map(tt.items, tt.fn)
			if diff := cmp.Diff(tt.expected, result); diff != "" {
				t.Errorf("Map() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestMapIntToString(t *testing.T) {
	tests := []struct {
		name     string
		items    []int
		fn       func(int) string
		expected []string
	}{
		{
			name:     "int to string conversion",
			items:    []int{1, 2, 3},
			fn:       func(x int) string { return strconv.Itoa(x) },
			expected: []string{"1", "2", "3"},
		},
		{
			name:     "custom formatting",
			items:    []int{1, 2, 3},
			fn:       func(x int) string { return "num_" + strconv.Itoa(x) },
			expected: []string{"num_1", "num_2", "num_3"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Map(tt.items, tt.fn)
			if diff := cmp.Diff(tt.expected, result); diff != "" {
				t.Errorf("Map() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestMapWithStructs(t *testing.T) {
	type Person struct {
		Name string
		Age  int
	}

	people := []Person{
		{Name: "Alice", Age: 30},
		{Name: "Bob", Age: 25},
		{Name: "Charlie", Age: 35},
	}

	names := Map(people, func(p Person) string { return p.Name })
	expectedNames := []string{"Alice", "Bob", "Charlie"}
	if diff := cmp.Diff(expectedNames, names); diff != "" {
		t.Errorf("Map() mismatch (-want +got):\n%s", diff)
	}

	ages := Map(people, func(p Person) int { return p.Age })
	expectedAges := []int{30, 25, 35}
	if diff := cmp.Diff(expectedAges, ages); diff != "" {
		t.Errorf("Map() mismatch (-want +got):\n%s", diff)
	}
}

func BenchmarkMapIntToInt(b *testing.B) {
	items := make([]int, 1000)
	for i := range items {
		items[i] = i
	}

	for b.Loop() {
		_ = Map(items, func(x int) int { return x * 2 })
	}
}

func BenchmarkMapStringToInt(b *testing.B) {
	items := make([]string, 1000)
	for i := range items {
		items[i] = strconv.Itoa(i)
	}

	for b.Loop() {
		_ = Map(items, func(s string) int { return len(s) })
	}
}
