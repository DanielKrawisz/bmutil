package identity

// CreateAddress populates the Address object within the identity based on the
// provided version and stream values and also generates the ripe.
func (id *Private) CreateAddress(version, stream uint64) error {
	var err error
	id.address, err = createAddress(version, stream, id.hash())
	if err != nil {
		return err
	}
	return nil
}
