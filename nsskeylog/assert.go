package nsskeylog

func assert(f bool, err error) error {
	if f {
		err = nil
	}
	return err
}
