package iter

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestFilter(t *testing.T) {
	tests := []struct {
		name     string
		items    []int
		fn       func(int) bool
		expected []int
	}{
		{
			name:     "filter even numbers",
			items:    []int{1, 2, 3, 4, 5, 6},
			fn:       func(x int) bool { return x%2 == 0 },
			expected: []int{2, 4, 6},
		},
		{
			name:     "filter odd numbers",
			items:    []int{1, 2, 3, 4, 5, 6},
			fn:       func(x int) bool { return x%2 != 0 },
			expected: []int{1, 3, 5},
		},
		{
			name:     "filter positive numbers",
			items:    []int{-2, -1, 0, 1, 2},
			fn:       func(x int) bool { return x > 0 },
			expected: []int{1, 2},
		},
		{
			name:     "filter none - all match",
			items:    []int{2, 4, 6, 8},
			fn:       func(x int) bool { return x%2 == 0 },
			expected: []int{2, 4, 6, 8},
		},
		{
			name:     "filter all - none match",
			items:    []int{1, 3, 5, 7},
			fn:       func(x int) bool { return x%2 == 0 },
			expected: []int{},
		},
		{
			name:     "empty slice",
			items:    []int{},
			fn:       func(x int) bool { return true },
			expected: []int{},
		},
		{
			name:     "single element matches",
			items:    []int{42},
			fn:       func(x int) bool { return x > 0 },
			expected: []int{42},
		},
		{
			name:     "single element does not match",
			items:    []int{-1},
			fn:       func(x int) bool { return x > 0 },
			expected: []int{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Filter(tt.items, tt.fn)
			if diff := cmp.Diff(tt.expected, result); diff != "" {
				t.Errorf("Filter() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestFilterStrings(t *testing.T) {
	tests := []struct {
		name     string
		items    []string
		fn       func(string) bool
		expected []string
	}{
		{
			name:     "filter non-empty strings",
			items:    []string{"a", "", "b", "", "c"},
			fn:       func(s string) bool { return s != "" },
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "filter by length",
			items:    []string{"a", "ab", "abc", "abcd"},
			fn:       func(s string) bool { return len(s) > 2 },
			expected: []string{"abc", "abcd"},
		},
		{
			name:     "filter by prefix",
			items:    []string{"foo", "bar", "foobar", "baz"},
			fn:       func(s string) bool { return len(s) >= 3 && s[:3] == "foo" },
			expected: []string{"foo", "foobar"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Filter(tt.items, tt.fn)
			if diff := cmp.Diff(tt.expected, result); diff != "" {
				t.Errorf("Filter() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestFilterWithStructs(t *testing.T) {
	type Person struct {
		Name string
		Age  int
	}

	people := []Person{
		{Name: "Alice", Age: 30},
		{Name: "Bob", Age: 17},
		{Name: "Charlie", Age: 25},
		{Name: "Diana", Age: 15},
	}

	adults := Filter(people, func(p Person) bool { return p.Age >= 18 })
	expectedAdults := []Person{
		{Name: "Alice", Age: 30},
		{Name: "Charlie", Age: 25},
	}
	if diff := cmp.Diff(expectedAdults, adults); diff != "" {
		t.Errorf("Filter() mismatch (-want +got):\n%s", diff)
	}
}

func BenchmarkFilter(b *testing.B) {
	items := make([]int, 1000)
	for i := range items {
		items[i] = i
	}

	for b.Loop() {
		_ = Filter(items, func(x int) bool { return x%2 == 0 })
	}
}
