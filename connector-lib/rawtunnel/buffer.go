package rawtunnel

// recvBuffer queues a pipe's received bytes in MaxDataBytes blocks until its
// Local accepts them. Received payloads are copied in, so a peer sending many
// tiny frames costs no more memory than one sending full ones, and flow
// control keeps the total at or below Window.
//
// The receive loop writes peek's slice to the Local without holding the lock
// while new bytes are appended. That is safe because appends only touch bytes
// past the end of every slice peek has returned, and consumed blocks are never
// reused.
type recvBuffer struct {
	blocks [][]byte
	head   int // read offset into blocks[0]
	size   int
}

func (b *recvBuffer) write(p []byte) {
	for len(p) > 0 {
		if n := len(b.blocks); n == 0 || len(b.blocks[n-1]) == MaxDataBytes {
			b.blocks = append(b.blocks, make([]byte, 0, MaxDataBytes))
		}
		last := &b.blocks[len(b.blocks)-1]
		k := min(len(p), MaxDataBytes-len(*last))
		*last = append(*last, p[:k]...)
		p = p[k:]
		b.size += k
	}
}

// peek returns the oldest unconsumed bytes, or nil when the buffer is empty.
func (b *recvBuffer) peek() []byte {
	if b.size == 0 {
		return nil
	}
	return b.blocks[0][b.head:]
}

func (b *recvBuffer) consume(n int) {
	b.head += n
	b.size -= n
	if b.head == len(b.blocks[0]) && (len(b.blocks) > 1 || b.head == MaxDataBytes) {
		b.blocks[0] = nil
		b.blocks = b.blocks[1:]
		b.head = 0
	}
}
