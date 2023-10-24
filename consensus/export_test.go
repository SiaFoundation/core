package consensus

// NewWork creates a Work instances for testing
func NewWork(n [32]byte) *Work {
	return &Work{
		n: n,
	}
}
