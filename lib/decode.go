/*
 * knoxite
 *     Copyright (c) 2016-2017, Christian Muehlhaeuser <muesli@gmail.com>
 *
 *   For license see LICENSE
 */

package knoxite

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/klauspost/reedsolomon"
)

// ChunkError records an error and the index
// that caused it.
type ChunkError struct {
	ChunkNum uint
}

func (e *ChunkError) Error() string {
	return fmt.Sprintf("Could not find chunk #%d", e.ChunkNum)
}

// SeekError records an error and the offset
// that caused it.
type SeekError struct {
	Offset int
}

func (e *SeekError) Error() string {
	return fmt.Sprintf("Could not seek to offset %d", e.Offset)
}

// CheckSumError records an error and the calculated
// checksums that did not match.
type CheckSumError struct {
	Method           string
	ExpectedCheckSum string
	FoundCheckSum    string
}

func (e *CheckSumError) Error() string {
	return fmt.Sprintf("%s mismatch, expected %s, got %s", e.Method, e.ExpectedCheckSum, e.FoundCheckSum)
}

// DataReconstructionError records an error and the associated
// parity information
type DataReconstructionError struct {
	Chunk          Chunk
	BlocksFound    uint
	FailedBackends uint
}

func (e *DataReconstructionError) Error() string {
	return fmt.Sprintf("Could not reconstruct data, got %d out of %d chunks (%d backends missing data)", e.BlocksFound, e.Chunk.DataParts, e.FailedBackends)
}

// DecodeSnapshot restores an entire snapshot to dst
func DecodeSnapshot(repository Repository, snapshot *Snapshot, dst string) (prog chan Progress, err error) {
	prog = make(chan Progress)
	go func() {
		for _, arc := range snapshot.Archives {
			path := filepath.Join(dst, arc.Path)
			err := DecodeArchive(prog, repository, arc, path)
			if err != nil {
				p := newProgressError(err)
				prog <- p
				break
			}
		}
		close(prog)
	}()

	return prog, nil
}

func decodeChunk(repository Repository, chunk Chunk, b []byte) ([]byte, error) {
	var err error
	if chunk.Encrypted == EncryptionAES {
		b, err = Decrypt(b, repository.Password)
		if err != nil {
			return []byte{}, err
		}
	}

	if chunk.Compressed == CompressionGZip {
		b, err = Uncompress(b)
		if err != nil {
			return []byte{}, err
		}
	}

	shadata := sha256.Sum256(b)
	shasum := hex.EncodeToString(shadata[:])

	if chunk.DecryptedShaSum != shasum {
		return []byte{}, &CheckSumError{"sha256", chunk.DecryptedShaSum, shasum}
	}

	return b, nil
}

func loadChunk(repository Repository, chunk Chunk) ([]byte, error) {
	if chunk.ParityParts > 0 {
		enc, err := reedsolomon.New(int(chunk.DataParts), int(chunk.ParityParts))
		if err != nil {
			return []byte{}, err
		}
		pars := make([][]byte, chunk.DataParts+chunk.ParityParts)
		parsFound := uint(0)
		parsMissing := 0

		// try to load all parts until we can successfully combine/reconstruct the chunk
		for i := 0; i < int(chunk.DataParts+chunk.ParityParts); i++ {
			var cerr error
			pars[i], cerr = repository.Backend.LoadChunk(chunk, uint(i))
			if cerr != nil {
				pars[i] = nil
				parsMissing++
				continue
			}
			parsFound++

			// check if we already have a sufficient amount of parts
			if parsFound >= chunk.DataParts {
				var b bytes.Buffer
				w := bufio.NewWriter(&b)

				// if more than one data-part was missing, we need to reconstruct the chunk
				if parsMissing > 0 {
					err = enc.Reconstruct(pars)
					if err != nil {
						continue
					}
				}
				err = enc.Join(w, pars, chunk.Size)
				if err != nil {
					// reconstruction failed, let's try it with another parity part
					continue
				}
				w.Flush()
				return decodeChunk(repository, chunk, b.Bytes())
			}
		}

		return []byte{}, &DataReconstructionError{chunk, parsFound, chunk.DataParts - parsFound}
	}

	b, err := repository.Backend.LoadChunk(chunk, 0)
	if err != nil {
		return []byte{}, err
	}
	return decodeChunk(repository, chunk, b)
}

// DecodeArchive restores a single archive to path
func DecodeArchive(progress chan Progress, repository Repository, arc Archive, path string) error {
	p := newProgress(&arc)

	if arc.Type == Directory {
		//fmt.Printf("Creating directory %s\n", path)
		os.MkdirAll(path, arc.Mode)
		p.TotalStatistics.Dirs++
		progress <- p
	} else if arc.Type == SymLink {
		//fmt.Printf("Creating symlink %s -> %s\n", path, arc.PointsTo)
		os.Symlink(arc.PointsTo, path)
		p.TotalStatistics.SymLinks++
		progress <- p
	} else if arc.Type == File {
		parts := uint(len(arc.Chunks))
		//fmt.Printf("Creating file %s (%d chunks).\n", path, parts)

		p.TotalStatistics.Files++
		p.TotalStatistics.Size = arc.Size
		p.TotalStatistics.StorageSize = arc.StorageSize
		progress <- p

		// FIXME: we don't always need to create the path
		// this is just a safety measure for now
		err := os.MkdirAll(filepath.Dir(path), 0755)
		if err != nil {
			return err
		}

		// write to disk
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, arc.Mode)
		if err != nil {
			return err
		}

		for i := uint(0); i < parts; i++ {
			idx, erri := arc.IndexOfChunk(i)
			if erri != nil {
				return erri
			}

			chunk := arc.Chunks[idx]
			b, errc := loadChunk(repository, chunk)
			if errc != nil {
				return errc
			}

			_, err = f.Write(b)
			if err != nil {
				return err
			}

			p.TotalStatistics.Transferred += uint64(len(b))
			p.CurrentItemStats.Transferred += uint64(len(b))
			progress <- p
			// fmt.Printf("Chunk OK: %d bytes, sha256: %s\n", size, chunk.DecryptedShaSum)
		}

		f.Sync()
		f.Close()

		// Restore modification time
		err = os.Chtimes(path, arc.ModTime, arc.ModTime)
		if err != nil {
			return err
		}
	}

	// Restore ownerships
	return os.Lchown(path, int(arc.UID), int(arc.GID))
}

var (
	cache map[string][]byte
	mutex = &sync.Mutex{}
)

func init() {
	cache = make(map[string][]byte)

}

// DecodeArchiveData returns the content of a single archive
func DecodeArchiveData(repository Repository, arc Archive) ([]byte, Stats, error) {
	var b []byte
	var stats Stats

	if arc.Type == File {
		parts := uint(len(arc.Chunks))

		for i := uint(0); i < parts; i++ {
			idx, err := arc.IndexOfChunk(i)
			if err != nil {
				return b, stats, err
			}

			chunk := arc.Chunks[idx]
			mutex.Lock()
			cd, ok := cache[chunk.ShaSum]
			if ok {
				fmt.Println("Using cached chunk", chunk.ShaSum)
			} else {
				cd, err = loadChunk(repository, chunk)
				if err != nil {
					return b, stats, err
				}
				cache[chunk.ShaSum] = cd
			}

			mutex.Unlock()
			b = append(b, cd...)
		}

		stats.StorageSize += arc.StorageSize
		stats.Size += arc.Size
		stats.Transferred += arc.Size
		stats.Files++
	}

	return b, stats, nil
}

func readArchiveChunk(repository Repository, arc Archive, chunkNum uint) (*[]byte, error) {
	var b []byte
	var err error

	idx, err := arc.IndexOfChunk(chunkNum)
	if err != nil {
		return &b, err
	}

	chunk := arc.Chunks[idx]
	mutex.Lock()
	cd, ok := cache[chunk.ShaSum]
	if !ok {
		cd, err = loadChunk(repository, chunk)
		if err != nil {
			return &b, err
		}
		cache[chunk.ShaSum] = cd
	}

	mutex.Unlock()
	b = append(b, cd...)

	return &b, nil
}

// ReadArchive reads from an archive
func ReadArchive(repository Repository, arc Archive, offset int, size int) (*[]byte, error) {
	var b []byte

	// fmt.Println("Read req:", offset, size)
	if arc.Type == File {
		neededPart, internalOffset, err := arc.ChunkForOffset(offset)
		if err != nil {
			return &b, err
		}

		for len(b) < size {
			if neededPart >= uint(len(arc.Chunks)) {
				return &b, nil
			}
			cd, err := readArchiveChunk(repository, arc, neededPart)
			if err != nil || len(*cd) == 0 {
				//return b, err
				panic(err)
			}

			d := (*cd)[internalOffset:]
			if err != nil || len(d) == 0 {
				//return b, err
				panic(err)
			}
			if len(d)+len(b) > size {
				b = append(b, d[:size-len(b)]...)
			} else {
				b = append(b, d...)
			}

			internalOffset = 0
			neededPart++
		}

		// cache the next block NOW
		go func() {
			readArchiveChunk(repository, arc, neededPart)
		}()
	}

	return &b, nil
}
