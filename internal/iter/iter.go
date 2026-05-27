package iter

// Keys returns a slice of the keys in a map.
func Keys[T comparable, U any](items map[T]U) []T {
	keys := make([]T, 0, len(items))
	for key := range items {
		keys = append(keys, key)
	}
	return keys
}

// Filter returns a slice of the items in a slice that satisfy the predicate.
func Filter[T any](items []T, fn func(T) bool) []T {
	result := make([]T, 0, len(items))
	for _, item := range items {
		if fn(item) {
			result = append(result, item)
		}
	}
	return result
}
