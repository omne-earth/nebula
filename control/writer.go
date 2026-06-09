package control

import "io"

// StringWriter is the sink a control command writes its response to. It is a thin
// convenience over io.Writer (GetWriter exposes the raw writer for json encoders etc.).
// Ported verbatim from the embedded sshd so command callbacks are unchanged; the embedded
// sshd (-tags sshd) and the control socket both hand commands one of these.
type StringWriter interface {
	WriteLine(string) error
	Write(string) error
	WriteBytes([]byte) error
	GetWriter() io.Writer
}

type stringWriter struct {
	w io.Writer
}

// NewStringWriter wraps an io.Writer (an ssh channel, a unix-socket conn, a test buffer)
// as a StringWriter for a command's response.
func NewStringWriter(w io.Writer) StringWriter {
	return &stringWriter{w: w}
}

func (w *stringWriter) WriteLine(s string) error {
	return w.Write(s + "\n")
}

func (w *stringWriter) Write(s string) error {
	_, err := w.w.Write([]byte(s))
	return err
}

func (w *stringWriter) WriteBytes(b []byte) error {
	_, err := w.w.Write(b)
	return err
}

func (w *stringWriter) GetWriter() io.Writer {
	return w.w
}
