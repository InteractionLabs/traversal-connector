package iter

import (
	"testing"
)

func TestKeys(t *testing.T) {
	tests := []struct {
		name     string
		items    map[int]string
		expected []int
	}{
		{
			name:     "basic map with int keys",
			items:    map[int]string{1: "one", 2: "two", 3: "three"},
			expected: []int{1, 2, 3},
		},
		{
			name:     "empty map",
			items:    map[int]string{},
			expected: []int{},
		},
		{
			name:     "single element",
			items:    map[int]string{42: "answer"},
			expected: []int{42},
		},
		{
			name:     "map with negative keys",
			items:    map[int]string{-1: "negative", 0: "zero", 1: "positive"},
			expected: []int{-1, 0, 1},
		},
		{
			name:     "map with zero values",
			items:    map[int]string{0: "", 1: "", 2: ""},
			expected: []int{0, 1, 2},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Keys(tt.items)
			// Since map iteration order is non-deterministic, we need to compare sets
			if !equalSets(result, tt.expected) {
				t.Errorf("Keys() mismatch: got %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestKeysStringToInt(t *testing.T) {
	tests := []struct {
		name     string
		items    map[string]int
		expected []string
	}{
		{
			name:     "string keys to int values",
			items:    map[string]int{"a": 1, "b": 2, "c": 3},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "empty string keys map",
			items:    map[string]int{},
			expected: []string{},
		},
		{
			name:     "single string key",
			items:    map[string]int{"hello": 42},
			expected: []string{"hello"},
		},
		{
			name:     "empty string as key",
			items:    map[string]int{"": 0, "a": 1},
			expected: []string{"", "a"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Keys(tt.items)
			if !equalSets(result, tt.expected) {
				t.Errorf("Keys() mismatch: got %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestKeysIntToString(t *testing.T) {
	tests := []struct {
		name     string
		items    map[int]string
		expected []int
	}{
		{
			name:     "int keys to string values",
			items:    map[int]string{1: "one", 2: "two", 3: "three"},
			expected: []int{1, 2, 3},
		},
		{
			name:     "large int keys",
			items:    map[int]string{1000: "thousand", 2000: "two thousand"},
			expected: []int{1000, 2000},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Keys(tt.items)
			if !equalSets(result, tt.expected) {
				t.Errorf("Keys() mismatch: got %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestKeysWithStructs(t *testing.T) {
	type Person struct {
		Name string
		Age  int
	}

	people := map[string]Person{
		"alice":   {Name: "Alice", Age: 30},
		"bob":     {Name: "Bob", Age: 25},
		"charlie": {Name: "Charlie", Age: 35},
	}

	keys := Keys(people)
	expectedKeys := []string{"alice", "bob", "charlie"}
	if !equalSets(keys, expectedKeys) {
		t.Errorf("Keys() mismatch: got %v, expected %v", keys, expectedKeys)
	}
}

func TestKeysWithCustomTypes(t *testing.T) {
	type Status int
	const (
		statusPending Status = iota
		StatusActive
		StatusCompleted
	)

	statusMap := map[Status]string{
		statusPending:   "pending",
		StatusActive:    "active",
		StatusCompleted: "completed",
	}

	keys := Keys(statusMap)
	expectedKeys := []Status{statusPending, StatusActive, StatusCompleted}
	if !equalSets(keys, expectedKeys) {
		t.Errorf("Keys() mismatch: got %v, expected %v", keys, expectedKeys)
	}
}

func BenchmarkKeysIntToString(b *testing.B) {
	items := make(map[int]string, 1000)
	for i := range 1000 {
		items[i] = "value"
	}

	for b.Loop() {
		_ = Keys(items)
	}
}

func BenchmarkKeysStringToInt(b *testing.B) {
	items := make(map[string]int, 1000)
	for i := range 1000 {
		items[string(rune(i))] = i
	}

	for b.Loop() {
		_ = Keys(items)
	}
}

// equalSets checks if two slices contain the same elements (order-independent).
func equalSets[T comparable](a, b []T) bool {
	if len(a) != len(b) {
		return false
	}

	// Create a map to count occurrences in a
	counts := make(map[T]int)
	for _, v := range a {
		counts[v]++
	}

	// Subtract counts for elements in b
	for _, v := range b {
		counts[v]--
		if counts[v] < 0 {
			return false
		}
	}

	// Check if all counts are zero
	for _, count := range counts {
		if count != 0 {
			return false
		}
	}

	return true
}
