package workspace

import "golang.org/x/sys/unix"

func renameNoReplace(from int, old string, to int, name string) error {
	return unix.RenameatxNp(from, old, to, name, unix.RENAME_EXCL)
}
