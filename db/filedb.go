package db

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// FileDB is a durable key/value store backed by an append-only log.
//
// Every mutation is appended as a length-prefixed, CRC-checked record and the
// live offsets are held in an in-memory index. Reads are one seek; writes are
// sequential. On open the log is replayed to rebuild the index, and a trailing
// partial record (a crash mid-write) is truncated away rather than failing the
// open. Compact rewrites the log with only the live records.
type FileDB struct {
	mu       sync.RWMutex
	path     string
	file     *os.File
	writer   *bufio.Writer
	offset   int64
	index    map[string]recordLoc
	deadKeys int
	closed   bool
	syncMode bool
}

type recordLoc struct {
	offset int64
	length uint32
}

const (
	opPut    byte = 1
	opDelete byte = 2

	// headerLen is: op(1) + keyLen(4) + valueLen(4) + crc(4).
	headerLen = 13
)

var crcTable = crc32.MakeTable(crc32.Castagnoli)

// Options configure a FileDB.
type Options struct {
	// Sync flushes to stable storage after every batch. Slower, but a power
	// loss cannot lose an acknowledged write.
	Sync bool
}

// OpenFile opens (or creates) a FileDB at path.
func OpenFile(path string, opts Options) (*FileDB, error) {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("db: creating %s: %w", dir, err)
		}
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, fmt.Errorf("db: opening %s: %w", path, err)
	}
	d := &FileDB{
		path:     path,
		file:     f,
		index:    make(map[string]recordLoc),
		syncMode: opts.Sync,
	}
	if err := d.replay(); err != nil {
		f.Close()
		return nil, err
	}
	d.writer = bufio.NewWriterSize(f, 64*1024)
	return d, nil
}

// replay rebuilds the in-memory index from the log, truncating any trailing
// partial record left behind by a crash.
func (d *FileDB) replay() error {
	stat, err := d.file.Stat()
	if err != nil {
		return err
	}
	size := stat.Size()
	r := bufio.NewReaderSize(io.NewSectionReader(d.file, 0, size), 64*1024)

	var pos int64
	header := make([]byte, headerLen)
	for {
		if _, err := io.ReadFull(r, header); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break // clean end, or a torn header
			}
			return fmt.Errorf("db: reading log at %d: %w", pos, err)
		}
		op := header[0]
		keyLen := binary.BigEndian.Uint32(header[1:5])
		valLen := binary.BigEndian.Uint32(header[5:9])
		want := binary.BigEndian.Uint32(header[9:13])

		if op != opPut && op != opDelete {
			break // corrupt record; everything after it is unusable
		}
		body := make([]byte, uint64(keyLen)+uint64(valLen))
		if _, err := io.ReadFull(r, body); err != nil {
			break // torn body
		}
		if crc32.Checksum(body, crcTable) != want {
			break // the record did not land intact
		}

		key := string(body[:keyLen])
		switch op {
		case opPut:
			if _, existed := d.index[key]; existed {
				d.deadKeys++
			}
			d.index[key] = recordLoc{offset: pos + headerLen + int64(keyLen), length: valLen}
		case opDelete:
			if _, existed := d.index[key]; existed {
				d.deadKeys++
			}
			delete(d.index, key)
		}
		pos += headerLen + int64(keyLen) + int64(valLen)
	}

	if pos != size {
		// Drop the damaged tail so the next append starts from a clean boundary.
		if err := d.file.Truncate(pos); err != nil {
			return fmt.Errorf("db: truncating damaged tail: %w", err)
		}
	}
	if _, err := d.file.Seek(pos, io.SeekStart); err != nil {
		return err
	}
	d.offset = pos
	return nil
}

func (d *FileDB) appendRecord(op byte, key, value []byte) error {
	body := make([]byte, 0, len(key)+len(value))
	body = append(body, key...)
	body = append(body, value...)

	var header [headerLen]byte
	header[0] = op
	binary.BigEndian.PutUint32(header[1:5], uint32(len(key)))
	binary.BigEndian.PutUint32(header[5:9], uint32(len(value)))
	binary.BigEndian.PutUint32(header[9:13], crc32.Checksum(body, crcTable))

	if _, err := d.writer.Write(header[:]); err != nil {
		return err
	}
	if _, err := d.writer.Write(body); err != nil {
		return err
	}

	recordStart := d.offset
	d.offset += headerLen + int64(len(key)) + int64(len(value))

	k := string(key)
	if _, existed := d.index[k]; existed {
		d.deadKeys++
	}
	if op == opDelete {
		delete(d.index, k)
	} else {
		d.index[k] = recordLoc{offset: recordStart + headerLen + int64(len(key)), length: uint32(len(value))}
	}
	return nil
}

func (d *FileDB) Put(key, value []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return errors.New("db: closed")
	}
	if err := d.appendRecord(opPut, key, value); err != nil {
		return err
	}
	return d.flushLocked()
}

func (d *FileDB) Delete(key []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return errors.New("db: closed")
	}
	if err := d.appendRecord(opDelete, key, nil); err != nil {
		return err
	}
	return d.flushLocked()
}

func (d *FileDB) flushLocked() error {
	if err := d.writer.Flush(); err != nil {
		return err
	}
	if d.syncMode {
		return d.file.Sync()
	}
	return nil
}

func (d *FileDB) Get(key []byte) ([]byte, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed {
		return nil, errors.New("db: closed")
	}
	loc, ok := d.index[string(key)]
	if !ok {
		return nil, ErrNotFound
	}
	if loc.length == 0 {
		return []byte{}, nil
	}
	// Buffered writes must reach the file before we can read them back.
	if d.writer.Buffered() > 0 {
		if err := d.writer.Flush(); err != nil {
			return nil, err
		}
	}
	out := make([]byte, loc.length)
	if _, err := d.file.ReadAt(out, loc.offset); err != nil {
		return nil, fmt.Errorf("db: reading value at %d: %w", loc.offset, err)
	}
	return out, nil
}

func (d *FileDB) Has(key []byte) (bool, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	_, ok := d.index[string(key)]
	return ok, nil
}

func (d *FileDB) Iterate(prefix []byte, fn func(key, value []byte) bool) error {
	d.mu.RLock()
	keys := make([]string, 0, len(d.index))
	for k := range d.index {
		if hasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	d.mu.RUnlock()

	sort.Strings(keys)
	for _, k := range keys {
		v, err := d.Get([]byte(k))
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		if !fn([]byte(k), v) {
			return nil
		}
	}
	return nil
}

func (d *FileDB) NewBatch() Batch { return &fileBatch{db: d} }

// Compact rewrites the log keeping only live records, reclaiming the space held
// by overwritten and deleted keys.
func (d *FileDB) Compact() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return errors.New("db: closed")
	}
	if err := d.writer.Flush(); err != nil {
		return err
	}

	// Snapshot the live set before touching the file.
	live := make(map[string][]byte, len(d.index))
	for k, loc := range d.index {
		buf := make([]byte, loc.length)
		if loc.length > 0 {
			if _, err := d.file.ReadAt(buf, loc.offset); err != nil {
				return fmt.Errorf("db: compaction read failed: %w", err)
			}
		}
		live[k] = buf
	}

	// Write to a temporary file and rename, so a crash mid-compaction leaves
	// the original log intact.
	tmpPath := d.path + ".compact"
	tmp, err := os.OpenFile(tmpPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	newIndex := make(map[string]recordLoc, len(live))
	w := bufio.NewWriterSize(tmp, 64*1024)
	var offset int64
	keys := make([]string, 0, len(live))
	for k := range live {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		value := live[k]
		body := append([]byte(k), value...)
		var header [headerLen]byte
		header[0] = opPut
		binary.BigEndian.PutUint32(header[1:5], uint32(len(k)))
		binary.BigEndian.PutUint32(header[5:9], uint32(len(value)))
		binary.BigEndian.PutUint32(header[9:13], crc32.Checksum(body, crcTable))
		if _, err := w.Write(header[:]); err != nil {
			tmp.Close()
			os.Remove(tmpPath)
			return err
		}
		if _, err := w.Write(body); err != nil {
			tmp.Close()
			os.Remove(tmpPath)
			return err
		}
		newIndex[k] = recordLoc{offset: offset + headerLen + int64(len(k)), length: uint32(len(value))}
		offset += headerLen + int64(len(k)) + int64(len(value))
	}
	if err := w.Flush(); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := d.file.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, d.path); err != nil {
		return err
	}

	f, err := os.OpenFile(d.path, os.O_RDWR, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		f.Close()
		return err
	}
	d.file = f
	d.writer = bufio.NewWriterSize(f, 64*1024)
	d.index = newIndex
	d.offset = offset
	d.deadKeys = 0
	return nil
}

// NeedsCompaction reports whether dead records outnumber live ones, the point
// at which a rewrite pays for itself.
func (d *FileDB) NeedsCompaction() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.deadKeys > len(d.index) && d.deadKeys > 1024
}

func (d *FileDB) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	if err := d.writer.Flush(); err != nil {
		d.file.Close()
		return err
	}
	if err := d.file.Sync(); err != nil {
		d.file.Close()
		return err
	}
	return d.file.Close()
}

type fileOp struct {
	key    []byte
	value  []byte
	delete bool
}

type fileBatch struct {
	db  *FileDB
	ops []fileOp
}

func (b *fileBatch) Put(key, value []byte) error {
	b.ops = append(b.ops, fileOp{key: clone(key), value: clone(value)})
	return nil
}

func (b *fileBatch) Delete(key []byte) error {
	b.ops = append(b.ops, fileOp{key: clone(key), delete: true})
	return nil
}

func (b *fileBatch) Len() int { return len(b.ops) }

func (b *fileBatch) Reset() { b.ops = b.ops[:0] }

func (b *fileBatch) Write() error {
	b.db.mu.Lock()
	defer b.db.mu.Unlock()
	if b.db.closed {
		return errors.New("db: closed")
	}
	for _, op := range b.ops {
		kind := opPut
		if op.delete {
			kind = opDelete
		}
		if err := b.db.appendRecord(kind, op.key, op.value); err != nil {
			return err
		}
	}
	b.ops = b.ops[:0]
	return b.db.flushLocked()
}
