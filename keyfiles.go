package main

import (
	"errors"
	"fmt"
	"os"
	"time"
)

type keyBackups struct {
	privatePath   string
	publicPath    string
	privateBackup string
	publicBackup  string
}

func newKeyBackups(keyPath string) keyBackups {
	return keyBackups{privatePath: keyPath, publicPath: keyPath + ".pub"}
}

func (backups *keyBackups) anyKeyExists() (bool, error) {
	private, err := pathExists(backups.privatePath)
	if err != nil {
		return false, err
	}
	public, err := pathExists(backups.publicPath)
	return private || public, err
}

func (backups *keyBackups) rejectDirectories() error {
	for _, path := range []string{backups.privatePath, backups.publicPath} {
		info, err := os.Stat(path)
		if err == nil && info.IsDir() {
			return fmt.Errorf("expected key files, but a directory exists at %q", path)
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect %q: %w", path, err)
		}
	}
	return nil
}

func (backups *keyBackups) moveAside(now time.Time, pid int) error {
	tag := fmt.Sprintf("%s.%d", now.Format("20060102150405"), pid)
	backups.privateBackup = backups.privatePath + ".bak." + tag
	backups.publicBackup = backups.publicPath + ".bak." + tag

	for _, destination := range []string{backups.privateBackup, backups.publicBackup} {
		exists, err := pathExists(destination)
		if err != nil {
			return err
		}
		if exists {
			return errors.New("a generated backup destination already exists; retry to get a new backup name")
		}
	}

	privateExists, err := pathExists(backups.privatePath)
	if err != nil {
		return err
	}
	if privateExists {
		if err := os.Rename(backups.privatePath, backups.privateBackup); err != nil {
			return fmt.Errorf("back up private key: %w", err)
		}
	} else {
		backups.privateBackup = ""
	}

	publicExists, err := pathExists(backups.publicPath)
	if err != nil {
		return errors.Join(err, backups.restore(false))
	}
	if publicExists {
		if err := os.Rename(backups.publicPath, backups.publicBackup); err != nil {
			return errors.Join(fmt.Errorf("back up public key: %w", err), backups.restore(false))
		}
	} else {
		backups.publicBackup = ""
	}
	return nil
}

func (backups *keyBackups) restore(removeGenerated bool) error {
	var restoreErrors []error
	if removeGenerated {
		for _, path := range []string{backups.privatePath, backups.publicPath} {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				restoreErrors = append(restoreErrors, fmt.Errorf("remove partial key %q: %w", path, err))
			}
		}
	}
	for _, pair := range [][2]string{
		{backups.privateBackup, backups.privatePath},
		{backups.publicBackup, backups.publicPath},
	} {
		if pair[0] == "" {
			continue
		}
		exists, err := pathExists(pair[0])
		if err != nil {
			restoreErrors = append(restoreErrors, err)
			continue
		}
		if exists {
			if err := os.Rename(pair[0], pair[1]); err != nil {
				restoreErrors = append(restoreErrors, fmt.Errorf("restore %q: %w", pair[1], err))
			}
		}
	}
	return errors.Join(restoreErrors...)
}

func (backups *keyBackups) discard() error {
	var removeErrors []error
	for _, path := range []string{backups.privateBackup, backups.publicBackup} {
		if path == "" {
			continue
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			removeErrors = append(removeErrors, fmt.Errorf("delete staged key file %q: %w", path, err))
		}
	}
	return errors.Join(removeErrors...)
}

func pathExists(path string) (bool, error) {
	_, err := os.Lstat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, fmt.Errorf("inspect %q: %w", path, err)
}
